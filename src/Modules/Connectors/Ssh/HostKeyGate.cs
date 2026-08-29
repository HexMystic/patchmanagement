using PatchManagement.Contracts.Connectors;
using Renci.SshNet.Common;

namespace PatchManagement.Connectors.Ssh;

/// <summary>
/// Applies the host-key decision for one leg of a connection: it holds the pin fetched before the
/// handshake, decides synchronously inside <c>HostKeyReceived</c>, and persists what it saw after.
///
/// <para><b>Why the pin is fetched first rather than looked up in the handler.</b> SSH.NET raises
/// <c>HostKeyReceived</c> synchronously mid-exchange, so a store lookup there would have to block on
/// an async database call — sync-over-async on a transport thread, which is how thread-pool
/// starvation gets built at 10,000 endpoints. Reading the pin before connecting and writing the
/// observation after leaves the handler doing nothing but a string comparison.</para>
///
/// <para><b>The identity is the configured address, not the socket's.</b> A chained hop is dialled at
/// <c>127.0.0.1:&lt;ephemeral&gt;</c> through a forward, so pinning against the dialled address would
/// pin a port that differs every connection and verify nothing. Every lookup and every write here
/// uses the hop's configured host and port.</para>
/// </summary>
internal sealed class HostKeyGate
{
    private readonly IHostKeyStore? _store;
    private readonly Guid _tenantId;
    private readonly string _host;
    private readonly int _port;
    private readonly EndpointHostKeys _known;
    private readonly bool _pinsOnFirstSight;

    private HostKeyObservation? _observed;

    private HostKeyGate(
        IHostKeyStore? store, Guid tenantId, string host, int port, EndpointHostKeys known, bool pinsOnFirstSight)
    {
        _store = store;
        _tenantId = tenantId;
        _host = host;
        _port = port;
        _known = known;
        _pinsOnFirstSight = pinsOnFirstSight;
    }

    /// <summary>Reads what is known about this endpoint's keys, before any socket is opened.</summary>
    public static async Task<HostKeyGate> OpenAsync(
        IHostKeyStore? store,
        Guid tenantId,
        string host,
        int port,
        bool pinsOnFirstSight,
        CancellationToken ct)
    {
        var known = store is null
            ? EndpointHostKeys.None
            : await store.FindAsync(tenantId, host, port, ct).ConfigureAwait(false);

        return new HostKeyGate(store, tenantId, host, port, known, pinsOnFirstSight);
    }

    /// <summary>True once a presented key has been judged and rejected.</summary>
    public bool Refused =>
        _observed is { Verdict: HostKeyVerdict.Changed or HostKeyVerdict.Unknown or HostKeyVerdict.Withdrawn };

    /// <summary>
    /// The <c>HostKeyReceived</c> handler — a thin adapter over <see cref="Observe"/> so the decision
    /// itself can be tested without constructing SSH.NET's <see cref="HostKeyEventArgs"/>, which needs
    /// a real <c>KeyHostAlgorithm</c> and therefore a real key.
    /// </summary>
    public void Inspect(object? sender, HostKeyEventArgs e) =>
        e.CanTrust = Observe(e.HostKeyName, e.FingerPrintSHA256, e.HostKey);

    /// <summary>
    /// Judges one presented key and remembers it. Returns whether the transport may trust it.
    /// Pure comparison — no I/O, because this runs synchronously inside the handshake.
    /// </summary>
    public bool Observe(string keyAlgorithm, string fingerprintSha256, byte[] publicKey)
    {
        var verdict = Judge(_known, fingerprintSha256, _pinsOnFirstSight);

        _observed = new HostKeyObservation(
            _tenantId, _host, _port, keyAlgorithm, fingerprintSha256, publicKey, verdict);

        return verdict is HostKeyVerdict.PinnedOnFirstSight or HostKeyVerdict.Verified;
    }

    /// <summary>
    /// The whole trust decision, as a pure function of the pin, what was presented and the policy.
    ///
    /// <para><b><see cref="HostKeyVerdict.Changed"/> does not consult the policy.</b> A changed key is
    /// refused whether or not the deployment allows unknown keys: <c>AllowUnknownHostKeys</c> answers
    /// "may we pin something we have never seen", which is a different question from "may a pinned
    /// endpoint's key silently become a different one". Letting the flag cover both would make the
    /// lab's convenience opt-in disable the only check that detects interception.</para>
    /// </summary>
    internal static HostKeyVerdict Judge(
        EndpointHostKeys known, string presentedFingerprint, bool pinsOnFirstSight)
    {
        // Closed FIRST, before anything else looks at the pin. A revoked or superseded endpoint has
        // no trusted row, so every later branch would read it as "nothing is pinned" and accept the
        // key as a first sighting — which is how a deliberately withdrawn key came to be re-accepted
        // on every connection.
        if (known.ClosedFingerprints.Contains(presentedFingerprint, StringComparer.Ordinal))
            return HostKeyVerdict.Withdrawn;

        if (known.Trusted is null)
            return pinsOnFirstSight ? HostKeyVerdict.PinnedOnFirstSight : HostKeyVerdict.Unknown;

        // Ordinal, not culture-aware: this is a base64 digest, and a culture-sensitive comparison of
        // one is a correctness bug waiting for a locale to expose it.
        return string.Equals(known.Trusted.FingerprintSha256, presentedFingerprint, StringComparison.Ordinal)
            ? HostKeyVerdict.Verified
            : HostKeyVerdict.Changed;
    }

    /// <summary>
    /// How long the audit write may take. Independent of the connect budget on purpose, and bounded
    /// on purpose.
    ///
    /// <para>It cannot share the connect token: a mismatch discovered as the budget expires is
    /// exactly when the record matters most, and writing under an already-cancelled token throws
    /// instead — losing the row AND replacing the refusal with a cancellation. It cannot be
    /// unbounded either (NEVER #5). This is a local database write rather than a remote endpoint
    /// call, so it is short; if the database cannot accept a single row in this long, the connection
    /// fails rather than proceeding unrecorded.</para>
    /// </summary>
    private static readonly TimeSpan AuditWriteBudget = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Persists the observation. No-ops when there is no store (the pre-D-301 posture, still the
    /// shape the unit suite and the lab fixture use) or when no key was ever presented.
    ///
    /// <para><b>Takes no cancellation token, deliberately.</b> An earlier version documented that the
    /// write was "not cancelled by the connect budget" while passing that exact token — the comment
    /// described an intent the code did not implement. Removing the parameter makes the guarantee
    /// structural rather than a promise in prose.</para>
    /// </summary>
    public async Task RecordAsync()
    {
        if (_store is null || _observed is null) return;

        using var audit = new CancellationTokenSource(AuditWriteBudget);
        await _store.RecordAsync(_observed, audit.Token).ConfigureAwait(false);
    }

    /// <summary>
    /// The typed refusal, naming both fingerprints. Host keys are public material, so printing them
    /// is safe — and it is the only detail that lets an operator tell a rebuilt host from an
    /// interception, which is the decision this refusal hands them.
    /// </summary>
    public ConnectorConnectException Refusal() => _observed!.Verdict switch
    {
        HostKeyVerdict.Withdrawn => new ConnectorConnectException(
            ConnectorOutcome.ProtocolError,
            $"The host key presented by {_host}:{_port} has been withdrawn (revoked or superseded). "
            + $"Presented {_observed.KeyAlgorithm} SHA256:{_observed.FingerprintSha256}. Refusing to "
            + "authenticate: a closed status is a decision already recorded about this exact key, so "
            + "it is not re-accepted as a first sighting. Promote it deliberately if it is trusted "
            + "again."),

        HostKeyVerdict.Changed => new ConnectorConnectException(
            ConnectorOutcome.ProtocolError,
            $"The host key presented by {_host}:{_port} is not the key pinned for it. "
            + $"Pinned {_known.Trusted!.KeyAlgorithm} SHA256:{_known.Trusted.FingerprintSha256}; "
            + $"presented {_observed.KeyAlgorithm} SHA256:{_observed.FingerprintSha256}. "
            + "Refusing to authenticate. Either this endpoint was rebuilt and its new key must be "
            + "reviewed and promoted, or something else is answering on its address — the presented "
            + "key is recorded as pending so the change is auditable either way."),

        _ => new ConnectorConnectException(
            ConnectorOutcome.ProtocolError,
            $"No host key is pinned for {_host}:{_port} and this deployment does not pin on first "
            + $"sight (Connectors:Security:AllowUnknownHostKeys is false). Presented "
            + $"{_observed.KeyAlgorithm} SHA256:{_observed.FingerprintSha256}, recorded as pending "
            + "for review."),
    };
}
