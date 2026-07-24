namespace PatchManagement.Content.Model;

/// <summary>
/// One provenance record: "feed <see cref="Source"/> contributed to this advisory/patch, retrieved
/// at <see cref="RetrievedAt"/>". Serialized into the required non-empty <c>provenance</c> jsonb
/// array (schemas/advisory.schema.json, schemas/patch.schema.json). Every input to a Phase 7 risk
/// score is therefore traceable to who said it and when (DIFFERENTIATORS #4).
///
/// <see cref="ContentHash"/> is the hash of the raw source payload, so a later re-fetch can prove
/// whether the source changed without diffing the whole feed.
/// </summary>
public sealed record ProvenanceEntry(
    string Source,
    DateTimeOffset RetrievedAt,
    string? SourceRecordId = null,
    string? Url = null,
    string? ContentHash = null);
