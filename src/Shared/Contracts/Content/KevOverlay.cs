namespace PatchManagement.Contracts.Content;

/// <summary>
/// A CISA KEV enrichment for the advisory (or advisories) whose <c>external_id</c> equals
/// <see cref="CveId"/>. KEV publishes no advisory — it asserts a CVE is known-exploited — so it is
/// applied as an OVERLAY: it sets <c>kev_*</c> columns and appends a <c>kev</c> provenance entry,
/// never inserting a row with <c>source = 'kev'</c> (which the DB CHECK forbids and which would let
/// one CVE exist as divergent duplicate rows). Applying an overlay to a CVE with no advisory yet is
/// a no-op that enriches zero rows — honest, and self-heals once the advisory is ingested.
/// </summary>
public sealed record KevOverlay(
    string CveId,
    DateOnly? DateAdded,
    DateOnly? DueDate,
    bool? KnownRansomwareUse,
    ProvenanceEntry Provenance);
