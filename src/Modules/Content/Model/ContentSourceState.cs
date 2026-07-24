namespace PatchManagement.Content.Model;

/// <summary>
/// The persisted state of a feed handed to its connector at the start of a run: which stream
/// (<see cref="Instance"/>), optionally where to fetch from (<see cref="Endpoint"/> — e.g. an
/// air-gapped mirror or the local <c>wsusscn2.cab</c> path), and the last incremental
/// <see cref="Cursor"/>. The connector reads the cursor to fetch only what changed and returns a
/// new one, which makes refresh incremental (Phase 5 exit criteria).
/// </summary>
public sealed record ContentSourceState(string Instance, string? Endpoint, string? Cursor);
