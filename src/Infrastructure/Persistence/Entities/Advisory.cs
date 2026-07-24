namespace PatchManagement.Persistence.Entities;

/// <summary>
/// A normalized vulnerability advisory — "why this matters" (Phase 5). The installable thing is a
/// <see cref="Patch"/>.
///
/// GLOBAL CONTENT — no <c>tenant_id</c>, no RLS (CLAUDE.md §4.1 exemption, ADR 0010).
/// Mirrors <c>schemas/advisory.schema.json</c>.
///
/// The CVSS / KEV / EPSS columns plus <see cref="Provenance"/> are what make a Phase 7 risk score
/// defensible: every input is stored with the source that supplied it (DIFFERENTIATORS #4).
/// </summary>
public sealed class Advisory
{
    public Guid Id { get; set; }

    /// <summary>nvd / kev / epss / usn / rhsa / msrc / wsusscn2. Unique with <see cref="ExternalId"/>.</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>The source's own id: CVE-2025-12345, USN-1234-1, RHSA-2025:0001.</summary>
    public string ExternalId { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// none / low / medium / high / critical / <b>unknown</b>. "unknown" is first-class: a source
    /// that does not state severity must never be made to fabricate one (HARD-PROBLEMS #8).
    /// </summary>
    public string Severity { get; set; } = "unknown";

    public DateTimeOffset? PublishedAt { get; set; }

    /// <summary>Set when the source retracts the advisory. Content retires; it is never deleted.</summary>
    public DateTimeOffset? WithdrawnAt { get; set; }

    public double? CvssBaseScore { get; set; }

    /// <summary>e.g. CVSS:3.1/AV:N/AC:L/... — kept so a score can be re-derived and audited.</summary>
    public string? CvssVector { get; set; }

    /// <summary>2.0 / 3.0 / 3.1 / 4.0 — a base score is meaningless without it.</summary>
    public string? CvssVersion { get; set; }

    /// <summary>CISA KEV membership. False also covers "evaluated, not listed".</summary>
    public bool KevListed { get; set; }

    public DateOnly? KevDateAdded { get; set; }

    /// <summary>EPSS exploit probability in [0,1] — a probability, not a percentage.</summary>
    public double? EpssScore { get; set; }

    public double? EpssPercentile { get; set; }

    public DateTimeOffset? EpssScoredAt { get; set; }

    /// <summary>
    /// jsonb ARRAY (never null, never empty): one entry per contributing source — who said this,
    /// when, from what URL, with what content hash. An advisory assembled from NVD + KEV + EPSS
    /// carries three entries. MUST be valid JSON; the <c>jsonb</c> column rejects anything else
    /// with Postgres <c>22P02</c>.
    /// </summary>
    public string Provenance { get; set; } = "[]";

    /// <summary>Pointer to the retained raw payload (path/URI) — not the payload itself.</summary>
    public string? RawRef { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
