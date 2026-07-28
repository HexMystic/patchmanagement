namespace PatchManagement.Content.Ingestion;

/// <summary>
/// The honest result of one feed sync — what was written and whether it worked. Mirrors what lands
/// on <c>content_sources</c> (<see cref="Status"/> ∈ ok/failed, plus the counts and cursor). A
/// failed sync carries <see cref="Error"/> for diagnostics; that string is a sanitized exception
/// message and never contains credentials (CLAUDE.md NEVER #1 — the content feeds are unauthenticated
/// public data anyway, but the invariant is upheld regardless).
/// </summary>
public sealed record SyncOutcome
{
    public required string Kind { get; init; }
    public required string Instance { get; init; }
    public required string Status { get; init; }

    public int AdvisoriesUpserted { get; init; }
    public int AffectsUpserted { get; init; }
    public int PatchesUpserted { get; init; }
    public int SupersedenceEdges { get; init; }
    public int OverlaysApplied { get; init; }

    public string? Cursor { get; init; }
    public string? Error { get; init; }

    public const string Ok = "ok";
    public const string Failed = "failed";
}
