namespace PatchManagement.Connectors.Ssh;

/// <summary>
/// The host key this deployment has pinned for an endpoint. Public material by definition — a host
/// key is what the server publishes — so NEVER #1/#2 are not engaged and this may be logged or
/// returned to a caller.
/// </summary>
public sealed record PinnedHostKey(string KeyAlgorithm, string FingerprintSha256);

/// <summary>What comparing a presented key against the pin established.</summary>
public enum HostKeyVerdict
{
    /// <summary>Nothing was pinned and this deployment pins on first sight. Accepted and pinned.</summary>
    PinnedOnFirstSight,

    /// <summary>The presented key is the pinned key. Accepted; the pin's last-verified moment advances.</summary>
    Verified,

    /// <summary>
    /// A key IS pinned and a DIFFERENT one was presented. <b>Always refused</b>, whatever the
    /// configuration says — this is the event the store exists to catch, and it is either a rebuilt
    /// host whose new key an operator must review or an interception. Nothing distinguishes the two
    /// from here, which is exactly why it is not ours to wave through.
    /// </summary>
    Changed,

    /// <summary>Nothing is pinned and this deployment does not pin on first sight. Refused, recorded.</summary>
    Unknown,
}

/// <summary>
/// One endpoint's host key as observed during a handshake, plus what comparison established.
/// </summary>
public sealed record HostKeyObservation(
    Guid TenantId,
    string Host,
    int Port,
    string KeyAlgorithm,
    string FingerprintSha256,
    byte[] PublicKey,
    HostKeyVerdict Verdict);

/// <summary>
/// The persistent verified-host-key store (D-301) — trust on first use, with the emphasis on
/// <b>persistence</b>. HARD-PROBLEMS #11 rejects TOFU without it outright: a pin that does not
/// survive a restart is indistinguishable from trusting everything.
///
/// <para><b>Declared here, implemented over the asset store.</b> The port belongs with the connector
/// that consults it; the implementation belongs with asset persistence, "where a fingerprint is just
/// another observed fact about a host" (HARD-PROBLEMS #11's owner note). That also keeps this module
/// free of any persistence dependency, which <c>ProviderNeutralityTests</c> and the Clean
/// Architecture layering both require.</para>
///
/// <para><b>Tenant-scoped.</b> Implementations write through the RLS-intercepted context, so a
/// fingerprint pinned by one tenant is neither visible to nor usable by another — two tenants
/// managing the same address are two independent trust decisions.</para>
/// </summary>
public interface IHostKeyStore
{
    /// <summary>The key currently trusted for this endpoint, or null if none is pinned yet.</summary>
    Task<PinnedHostKey?> FindTrustedAsync(Guid tenantId, string host, int port, CancellationToken ct);

    /// <summary>
    /// Records what was observed. A first sighting under a pinning policy becomes the trusted pin; a
    /// key that was refused is recorded <c>pending</c> so an operator can see what was presented.
    ///
    /// <para><b>Refusals are written, not just returned.</b> "The key at this endpoint changed on
    /// date X" is the security-relevant event, and a refusal that left no row would leave the estate
    /// with no record that it happened.</para>
    /// </summary>
    Task RecordAsync(HostKeyObservation observation, CancellationToken ct);
}
