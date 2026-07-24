using PatchManagement.Content.Model;

namespace PatchManagement.Content.Abstractions;

/// <summary>
/// A single feed connector: fetches its source (via an injected <see cref="IHttpContentFetcher"/>
/// or file source, so tests use recorded payloads and never hammer live APIs) and NORMALIZES it
/// into a <see cref="NormalizedBatch"/> against the frozen Phase-1 vocabulary. A connector performs
/// no database writes — persistence is <c>ContentSyncService</c>'s job — which keeps it a pure,
/// deterministic transform.
///
/// Every implementation is time-bounded via the <see cref="System.Threading.CancellationToken"/>
/// and idempotent by construction: the same input yields the same batch, and the store upserts
/// against the frozen unique keys, so a re-run duplicates nothing (CLAUDE.md NEVER #5, HARD-PROBLEMS #6).
/// </summary>
public interface IContentConnector
{
    /// <summary>The feed kind — one of <see cref="Feeds"/>. Matches <c>content_sources.kind</c>.</summary>
    string Kind { get; }

    /// <summary>Fetch and normalize. <paramref name="state"/> carries the incremental cursor.</summary>
    Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct);
}
