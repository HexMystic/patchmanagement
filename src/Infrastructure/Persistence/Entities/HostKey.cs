namespace PatchManagement.Persistence.Entities;

/// <summary>
/// A host key observed at an endpoint, and whether this deployment trusts it — the store D-301 was
/// deferred for.
///
/// <para>Until this exists, <c>ConnectorSecurityOptions.AllowUnknownHostKeys</c> is a blanket yes/no:
/// production either refuses every connection or accepts whatever answers on the target's address
/// and then sends it a private key. The store is what lets a first sighting be pinned and a
/// <b>changed</b> key be refused, which is the property that actually authenticates the endpoint.</para>
///
/// <para><b>Nothing here is secret.</b> A host key is public material by definition, so
/// <see cref="PublicKey"/> is stored verbatim — NEVER #1/#2 are not engaged. It is kept alongside the
/// fingerprint so comparison can be exact rather than by digest, and so a fingerprint can be
/// recomputed if the hash of record ever changes.</para>
///
/// <para><b>Rotation supersedes; it does not overwrite.</b> A legitimate rebuild changes a host key,
/// and "the key at this endpoint changed on date X" is the security-relevant event this table exists
/// to capture. Overwriting the row would destroy exactly that, so the old row is retained with
/// <see cref="SupersededAt"/> set, and the unique index admits only one <c>trusted</c> key per
/// endpoint so "which key do we trust" always has one answer.</para>
/// </summary>
public sealed class HostKey
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }

    /// <summary>The host as connected to — the only identity available at handshake time.</summary>
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; }

    /// <summary>The asset this endpoint turned out to be, once one is known. Null until then.</summary>
    public Guid? AssetId { get; set; }

    /// <summary>e.g. <c>ssh-ed25519</c>, <c>ecdsa-sha2-nistp256</c>, <c>ssh-rsa</c>.</summary>
    public string KeyAlgorithm { get; set; } = string.Empty;

    /// <summary>Base64 SHA-256 of the key, the format OpenSSH prints. The compared value.</summary>
    public string FingerprintSha256 { get; set; } = string.Empty;

    /// <summary>The presented public key, verbatim. Public material — not a secret.</summary>
    public byte[] PublicKey { get; set; } = [];

    public string Status { get; set; } = HostKeyStatuses.Trusted;

    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastVerifiedAt { get; set; }

    /// <summary>Set when the key stops being the trusted one. Null while it is.</summary>
    public DateTimeOffset? SupersededAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Lifecycle of a pinned host key.</summary>
public static class HostKeyStatuses
{
    /// <summary>The pin. At most one per endpoint, enforced by a partial unique index.</summary>
    public const string Trusted = "trusted";

    /// <summary>Seen, not yet accepted — a first sighting awaiting an operator, or a changed key.</summary>
    public const string Pending = "pending";

    /// <summary>Was trusted; replaced by a later key at the same endpoint.</summary>
    public const string Superseded = "superseded";

    /// <summary>Withdrawn deliberately rather than replaced.</summary>
    public const string Revoked = "revoked";

    public static readonly IReadOnlyList<string> All = [Trusted, Pending, Superseded, Revoked];

    /// <summary>Statuses that require <c>superseded_at</c> to be set.</summary>
    public static readonly IReadOnlyList<string> Closed = [Superseded, Revoked];
}
