namespace PatchManagement.Content.Model;

/// <summary>
/// An installable patch ready to upsert into <c>patches</c>. Produced by the USN / RHSA / MSRC /
/// wsusscn2 / DSA connectors — the frozen <c>patches.source</c> vocabulary.
///
/// <see cref="Reversible"/> and <see cref="RequiresReboot"/> default to <c>false</c> when the
/// source does not say, because false is the safe answer: it gates rollback OFF and never
/// under-counts a maintenance window into thinking no reboot is needed (DIFFERENTIATORS #1/#3).
/// </summary>
public sealed record NormalizedPatch
{
    /// <summary>Publisher of the installable update: usn / rhsa / msrc / wsusscn2 / dsa.</summary>
    public required string Source { get; init; }

    /// <summary>The vendor's patch id: KB5034441, USN-6789-1, RHSA-2025:0001.</summary>
    public required string VendorId { get; init; }

    public required string Title { get; init; }

    public bool Reversible { get; init; }
    public bool RequiresReboot { get; init; }

    /// <summary>Vendor's own category, raw as sourced ('Security Updates', 'Driver', …).</summary>
    public string? Classification { get; init; }

    public DateTimeOffset? PublishedAt { get; init; }
    public DateTimeOffset? WithdrawnAt { get; init; }

    /// <summary>Open extension point, serialized to the <c>source_metadata</c> jsonb column. Raw JSON.</summary>
    public string? SourceMetadataJson { get; init; }

    /// <summary>REQUIRED, non-empty (DB CHECK enforces non-empty).</summary>
    public required IReadOnlyList<ProvenanceEntry> Provenance { get; init; }

    /// <summary>
    /// Vendor ids of patches this one supersedes. Persisted as <c>patch_supersedence</c> edges
    /// (patch_id = the older/superseded, superseded_by_patch_id = this one). Edges only form once
    /// BOTH patches are ingested; connectors that carry supersedence (wsusscn2) upsert all patches
    /// before their edges so the resolution succeeds (HARD-PROBLEMS #4).
    /// </summary>
    public IReadOnlyList<string> Supersedes { get; init; } = [];
}
