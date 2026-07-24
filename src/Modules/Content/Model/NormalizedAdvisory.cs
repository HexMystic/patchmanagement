namespace PatchManagement.Content.Model;

/// <summary>
/// A publisher-side advisory ready to upsert into <c>advisories</c> (+ its <c>advisory_affects</c>
/// fix statements). Produced by the NVD / USN / RHSA / MSRC / DSA connectors — the feeds in the
/// frozen <c>advisories.source</c> vocabulary. KEV/EPSS never produce these; they are overlays
/// (see <see cref="KevOverlay"/> / <see cref="EpssOverlay"/>).
/// </summary>
public sealed record NormalizedAdvisory
{
    /// <summary>Publisher: nvd / usn / rhsa / msrc / dsa. The DB CHECK rejects anything else.</summary>
    public required string Source { get; init; }

    /// <summary>The source's own id: CVE-2025-12345, USN-6789-1, RHSA-2025:0001, DSA-5678-1.</summary>
    public required string ExternalId { get; init; }

    public required string Title { get; init; }

    /// <summary>none/low/medium/high/critical/unknown. Defaults to <c>unknown</c> — a source that
    /// states no severity is never made to fabricate one (HARD-PROBLEMS #8).</summary>
    public string Severity { get; init; } = "unknown";

    public DateTimeOffset? PublishedAt { get; init; }
    public DateTimeOffset? WithdrawnAt { get; init; }

    public double? CvssBaseScore { get; init; }
    public string? CvssVector { get; init; }
    public string? CvssVersion { get; init; }

    /// <summary>Which feed supplied the CVSS score — NVD and a vendor routinely disagree.</summary>
    public string? CvssSource { get; init; }

    /// <summary>Open extension point, serialized to the <c>source_metadata</c> jsonb column. Raw JSON.</summary>
    public string? SourceMetadataJson { get; init; }

    /// <summary>Pointer to the retained raw payload (path/URI) — not the payload itself.</summary>
    public string? RawRef { get; init; }

    /// <summary>REQUIRED, non-empty. One entry per contributing feed (DB CHECK enforces non-empty).</summary>
    public required IReadOnlyList<ProvenanceEntry> Provenance { get; init; }

    public IReadOnlyList<NormalizedAffect> Affects { get; init; } = [];
}
