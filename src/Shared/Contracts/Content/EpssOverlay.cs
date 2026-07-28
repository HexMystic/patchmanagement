namespace PatchManagement.Contracts.Content;

/// <summary>
/// A FIRST EPSS enrichment for the advisory (or advisories) whose <c>external_id</c> equals
/// <see cref="CveId"/>. Like KEV, EPSS is an OVERLAY: it sets <c>epss_*</c> columns and appends an
/// <c>epss</c> provenance entry, never a row with <c>source = 'epss'</c>.
///
/// <see cref="Score"/> and <see cref="Percentile"/> are probabilities in [0,1] — NOT percentages.
/// The DB CHECK rejects anything outside [0,1], so a connector that divides by 100 by mistake fails
/// loudly rather than silently inflating every Phase 7 risk score.
/// </summary>
public sealed record EpssOverlay(
    string CveId,
    double Score,
    double? Percentile,
    DateTimeOffset? ScoredAt,
    ProvenanceEntry Provenance);
