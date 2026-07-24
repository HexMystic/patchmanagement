namespace PatchManagement.Persistence.Entities;

/// <summary>
/// A configured upstream content feed and its incremental-sync bookmark (Phase 5).
///
/// GLOBAL CONTENT — no <c>tenant_id</c>, no RLS (CLAUDE.md §4.1 exemption, ADR 0010): the feeds
/// are the same for every tenant. Read-only to <c>patchmgmt_app</c>; written by
/// <c>patchmgmt_content</c>.
/// </summary>
public sealed class ContentSource
{
    public Guid Id { get; set; }

    /// <summary>nvd / kev / epss / usn / rhsa / msrc / wsusscn2.</summary>
    public string Kind { get; set; } = string.Empty;

    /// <summary>
    /// Distinguishes MULTIPLE feeds of the same kind, which is the normal case rather than the
    /// exception: Red Hat publishes OVAL per major version (<c>rhel-8</c>, <c>rhel-9</c>), Ubuntu
    /// per release, Debian per suite. Keying on <see cref="Kind"/> alone would cap the whole
    /// deployment at seven feeds ever. Free-form and source-defined; <c>default</c> for feeds that
    /// genuinely have one stream (NVD, KEV, EPSS).
    /// </summary>
    public string Instance { get; set; } = "default";

    /// <summary>
    /// Where to fetch from. Present so an air-gapped or on-prem install can point at an internal
    /// mirror (e.g. a locally hosted <c>wsusscn2.cab</c>) without a schema change. Credentials are
    /// NEVER stored here — this is a location, not a secret (CLAUDE.md NEVER #1).
    /// </summary>
    public string? Endpoint { get; set; }

    public bool Enabled { get; set; } = true;

    public DateTimeOffset? LastSyncAt { get; set; }

    /// <summary>
    /// Opaque, source-defined incremental bookmark (a timestamp, ETag, or page token). Never
    /// interpreted here — only the Phase 5 connector for this <see cref="Kind"/> understands it.
    /// </summary>
    public string? Cursor { get; set; }

    /// <summary>
    /// Honest sync outcome: ok / failed / never-run. There is no "assumed ok" — a feed that has
    /// never run says so, so a stale catalogue can never masquerade as current (HARD-PROBLEMS #8).
    /// </summary>
    public string LastStatus { get; set; } = "never-run";

    /// <summary>Diagnostic for the last failure. Never contains credentials (CLAUDE.md NEVER #1).</summary>
    public string? LastError { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
