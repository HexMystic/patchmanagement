namespace PatchManagement.Content.Model;

/// <summary>
/// The full result of one connector run: everything to persist plus the new incremental
/// <see cref="Cursor"/>. A connector is a PURE transform (feed payload → this batch); persistence
/// and transaction control live in <c>ContentSyncService</c>, which keeps connectors trivially
/// testable without a database.
/// </summary>
public sealed record NormalizedBatch
{
    public IReadOnlyList<NormalizedAdvisory> Advisories { get; init; } = [];
    public IReadOnlyList<NormalizedPatch> Patches { get; init; } = [];
    public IReadOnlyList<KevOverlay> KevOverlays { get; init; } = [];
    public IReadOnlyList<EpssOverlay> EpssOverlays { get; init; } = [];

    /// <summary>
    /// The new opaque incremental bookmark to persist on <c>content_sources.cursor</c>, or the old
    /// one unchanged / null. Never interpreted outside the connector that produced it.
    /// </summary>
    public string? Cursor { get; init; }

    public static NormalizedBatch Empty { get; } = new();
}
