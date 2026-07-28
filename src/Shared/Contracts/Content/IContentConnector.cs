namespace PatchManagement.Contracts.Content;

/// <summary>
/// A single feed connector: fetches its source (via an injected <c>IHttpContentFetcher</c> or file
/// source, so tests use recorded payloads and never hammer live APIs) and NORMALIZES it into a
/// <see cref="NormalizedBatch"/> against the frozen Phase-1 vocabulary. A connector performs no
/// database writes — persistence is <c>ContentSyncService</c>'s job — which keeps it a pure,
/// deterministic transform.
///
/// Every implementation is time-bounded via the <see cref="System.Threading.CancellationToken"/>
/// and idempotent by construction: the same input yields the same batch, and the store upserts
/// against the frozen unique keys, so a re-run duplicates nothing (CLAUDE.md NEVER #5, HARD-PROBLEMS #6).
///
/// <para>It lives in Contracts, not in the Content module, for the reason
/// <c>docs/adr/0018-content-contract-surface.md</c> records: the host-discovery guard must assert
/// through a type the integration-test project already has, or the test project would need a
/// reference to the module — which puts the module DLL in the TEST output, lets
/// <c>CompositionRoot</c>'s base-directory scan succeed on that copy, and makes the guard incapable
/// of failing. The transport-shaped seams (<c>IContentStore</c>, <c>IContentConnectionFactory</c>)
/// deliberately stay in the module: they carry Npgsql types, and Contracts takes no database
/// dependency. Same split, and same reasoning, as ADR 0017 applied to <c>IEndpointConnector</c>.</para>
/// </summary>
public interface IContentConnector
{
    /// <summary>The feed kind — one of <see cref="Feeds"/>. Matches <c>content_sources.kind</c>.</summary>
    string Kind { get; }

    /// <summary>Fetch and normalize. <paramref name="state"/> carries the incremental cursor.</summary>
    Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct);
}
