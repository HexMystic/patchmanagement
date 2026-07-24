namespace PatchManagement.Persistence.Entities;

/// <summary>
/// One fix statement: "advisory X is fixed in version Y of package Z, on release P".
///
/// GLOBAL CONTENT — no <c>tenant_id</c>, no RLS (CLAUDE.md §4.1 exemption, ADR 0010).
///
/// ROW GRAIN — one row per (advisory, package, ecosystem, <see cref="Platform"/>). A single
/// advisory routinely fixes the SAME package at DIFFERENT versions per release: one USN covers
/// every supported Ubuntu release, one Debian DSA spans bullseye and bookworm, one MSRC CVE spans
/// Windows 10 21H2 / 11 23H2 / Server 2022. Keying without <see cref="Platform"/> would reject
/// those legitimate rows and lose the information Phase 6 needs to pick the right fix for a host.
///
/// <see cref="Platform"/> and <see cref="FixedVersion"/> are stored RAW AS SOURCED — never parsed,
/// split, or canonicalized here. The Phase 6 per-ecosystem comparator owns interpretation
/// (ADR 0011, HARD-PROBLEMS #3).
/// </summary>
public sealed class AdvisoryAffects
{
    public Guid Id { get; set; }

    public Guid AdvisoryId { get; set; }

    public string PackageName { get; set; } = string.Empty;

    /// <summary>
    /// deb / rpm / windows — the ONLY interpreted field here: it selects the version comparator
    /// (HARD-PROBLEMS #3). A fourth ecosystem needs a comparator, so widening the CHECK is the
    /// correct gate.
    /// </summary>
    public string Ecosystem { get; set; } = string.Empty;

    /// <summary>
    /// Release/product scope this fix applies to, raw as sourced: <c>ubuntu:22.04</c>,
    /// <c>rhel:9</c>, <c>windows:server-2022</c>. NULL when the source states no release scope
    /// (e.g. NVD CPE ranges) — never a fabricated sentinel (HARD-PROBLEMS #8). Part of the row's
    /// identity, so the unique index treats NULLs as EQUAL (<c>NULLS NOT DISTINCT</c>) — otherwise
    /// repeated NULL-platform rows would duplicate and break idempotent upsert.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// The fixed version, raw as sourced: <c>3.0.2-0ubuntu1.16</c>, <c>0:1.2.3-4.el9_3</c>,
    /// <c>10.0.19045.4046</c>. NULL when no fix is available yet. Payload, not key — one
    /// (advisory, package, ecosystem, platform) has exactly one fix; two would be a content
    /// conflict to surface, not to store twice.
    /// </summary>
    public string? FixedVersion { get; set; }

    /// <summary>
    /// True when the distro backported the fix without an upstream version bump — the case that
    /// makes naive "installed &lt; upstream fixed" comparison produce mass false positives
    /// (HARD-PROBLEMS #2).
    /// </summary>
    public bool Backported { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public Advisory? Advisory { get; set; }
}
