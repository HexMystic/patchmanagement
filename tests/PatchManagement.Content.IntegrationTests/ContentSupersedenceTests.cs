using Microsoft.Extensions.Logging.Abstractions;
using PatchManagement.Content.Ingestion;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// Phase 5 exit criterion (f): <b>supersedence chains resolve, including the both-patches-required
/// ordering</b>.
///
/// <para>HARD-PROBLEMS #4: a host missing a superseded patch must be told to install the
/// <em>superseding</em> one, resolved through a DAG to its effective head. Phase 5 does not do that
/// resolution — Phase 6 does — but Phase 5 writes the graph it walks, so an edge Phase 5 drops is a
/// redundant or impossible deployment plan later, with nothing at assessment time to reveal it.</para>
///
/// <para>The ordering problem is the sharp edge. An edge needs BOTH endpoints ingested, and vendors
/// do not publish a superseding patch after the patch it supersedes. <c>ContentSyncService</c>
/// answers this with two passes over the batch — all patches, then all edges — and that is asserted
/// here through the service rather than the store, because the store alone cannot exhibit it.</para>
/// </summary>
[Collection(ContentPostgresCollection.Name)]
public sealed class ContentSupersedenceTests(ContentPostgresFixture fx)
{
    private readonly ContentStore _store = new();

    /// <summary>
    /// The ordering guarantee, end to end: the superseding patch appears FIRST in the batch and
    /// names a patch that has not been ingested yet. A single-pass loop would resolve nothing and
    /// silently write zero edges. Ordered deliberately so a one-pass implementation fails.
    /// </summary>
    [Fact]
    public async Task An_edge_resolves_when_the_superseded_patch_appears_later_in_the_same_batch()
    {
        var older = $"KB{Catalogue.Uid()}";
        var newer = $"KB{Catalogue.Uid()}";

        var batch = new NormalizedBatch
        {
            Patches =
            [
                Catalogue.Patch(Feeds.Wsusscn2, newer, supersedes: [older]),
                Catalogue.Patch(Feeds.Wsusscn2, older),
            ],
        };

        var outcome = await RunSyncAsync(batch, $"wsus-{Catalogue.Uid()}");

        Assert.Equal(SyncOutcome.Ok, outcome.Status);
        Assert.Equal(2, outcome.PatchesUpserted);
        Assert.Equal(1, outcome.SupersedenceEdges);

        await using var conn = await fx.OpenAsync();
        Assert.Contains((older, newer), await Catalogue.EdgesAsync(conn, Feeds.Wsusscn2));
    }

    /// <summary>
    /// Across batches the edge cannot form yet — the superseded patch does not exist, so there is
    /// nothing to point at. It must not throw, must not invent a patch row, and must report zero
    /// honestly; then form on the run where the other endpoint arrives.
    /// </summary>
    [Fact]
    public async Task An_edge_naming_an_uningested_patch_forms_on_the_run_that_supplies_it()
    {
        await using var conn = await fx.OpenAsync();
        var older = $"KB{Catalogue.Uid()}";
        var newer = $"KB{Catalogue.Uid()}";

        await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertPatchAsync(conn, tx, Catalogue.Patch(Feeds.Wsusscn2, newer), default));

        var premature = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, newer, older, default));
        Assert.Equal(0, premature);

        await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertPatchAsync(conn, tx, Catalogue.Patch(Feeds.Wsusscn2, older), default));

        var resolved = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, newer, older, default));
        Assert.Equal(1, resolved);
    }

    /// <summary>
    /// A three-patch chain, which is what "resolve to the effective head" needs: from the oldest
    /// patch a walk must reach exactly one terminal patch. Asserted with the same recursive walk
    /// Phase 6 will perform, so this proves the shape is traversable rather than merely present.
    /// </summary>
    [Fact]
    public async Task A_three_patch_chain_walks_to_a_single_effective_head()
    {
        await using var conn = await fx.OpenAsync();
        var a = $"KB{Catalogue.Uid()}";
        var b = $"KB{Catalogue.Uid()}";
        var c = $"KB{Catalogue.Uid()}";

        // c supersedes b supersedes a.
        foreach (var vendorId in new[] { a, b, c })
            await Catalogue.CommittedAsync(conn, tx =>
                _store.UpsertPatchAsync(conn, tx, Catalogue.Patch(Feeds.Wsusscn2, vendorId), default));

        await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, b, a, default));
        await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, c, b, default));

        Assert.Equal([c], await HeadsOfAsync(conn, a));
    }

    [Fact]
    public async Task The_same_edge_seen_twice_is_stored_once()
    {
        await using var conn = await fx.OpenAsync();
        var older = $"KB{Catalogue.Uid()}";
        var newer = $"KB{Catalogue.Uid()}";

        foreach (var vendorId in new[] { older, newer })
            await Catalogue.CommittedAsync(conn, tx =>
                _store.UpsertPatchAsync(conn, tx, Catalogue.Patch(Feeds.Wsusscn2, vendorId), default));

        Assert.Equal(1, await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, newer, older, default)));
        Assert.Equal(0, await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, newer, older, default)));

        var edges = await Catalogue.EdgesAsync(conn, Feeds.Wsusscn2);
        Assert.Single(edges, e => e == (older, newer));
    }

    /// <summary>
    /// A feed that names a patch as its own predecessor must be refused by the store, not by the
    /// CHECK: a 23514 mid-batch aborts the whole feed's transaction, so one malformed record would
    /// cost every good record beside it.
    /// </summary>
    [Fact]
    public async Task A_patch_that_supersedes_itself_is_dropped_rather_than_failing_the_batch()
    {
        await using var conn = await fx.OpenAsync();
        var kb = $"KB{Catalogue.Uid()}";

        await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertPatchAsync(conn, tx, Catalogue.Patch(Feeds.Wsusscn2, kb), default));

        var edges = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, kb, kb, default));

        Assert.Equal(0, edges);
    }

    /// <summary>
    /// CHARACTERIZATION — this pins a REAL GAP, not a guarantee.
    ///
    /// <para>HARD-PROBLEMS #4 calls for the graph to be a DAG and for cycles to be "detected and
    /// broken defensively". <c>ck_patch_supersedence_no_self_loop</c> rejects a 1-cycle and
    /// <c>UpsertSupersedenceAsync</c> filters it, but <b>nothing rejects a 2-cycle</b>: A supersedes
    /// B and B supersedes A both insert cleanly, and the table named for a DAG then holds one.</para>
    ///
    /// <para>Whose bug it is, stated rather than assumed: HARD-PROBLEMS assigns cycle-breaking to
    /// assessment, so Phase 6 must be cycle-safe regardless — a real feed can contradict itself and
    /// Phase 5 must not reject good content over it. What is missing is that the walk above
    /// (<c>HeadsOfAsync</c>, and every walk shaped like it) does not terminate on this data, and
    /// nothing tells Phase 6 that. Recorded as <b>D-503</b>, owner Phase 6, gated: the effective-head
    /// resolution cannot be claimed until it terminates on a cyclic graph.</para>
    /// </summary>
    [Fact]
    public async Task A_two_patch_cycle_is_accepted_today_and_the_graph_is_not_provably_acyclic()
    {
        await using var conn = await fx.OpenAsync();
        var a = $"KB{Catalogue.Uid()}";
        var b = $"KB{Catalogue.Uid()}";

        foreach (var vendorId in new[] { a, b })
            await Catalogue.CommittedAsync(conn, tx =>
                _store.UpsertPatchAsync(conn, tx, Catalogue.Patch(Feeds.Wsusscn2, vendorId), default));

        var forward = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, b, a, default));
        var backward = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertSupersedenceAsync(conn, tx, Feeds.Wsusscn2, a, b, default));

        // Both accepted. Neither the CHECK nor the store's self-loop filter sees a 2-cycle.
        Assert.Equal(1, forward);
        Assert.Equal(1, backward);
    }

    // -----------------------------------------------------------------------------------------

    private async Task<SyncOutcome> RunSyncAsync(NormalizedBatch batch, string instance)
    {
        var service = new ContentSyncService(
            _store, new FixtureConnectionFactory(fx), NullLogger<ContentSyncService>.Instance);

        return await service.RunAsync(
            new ScriptedConnector(Feeds.Wsusscn2, batch), instance, endpoint: null, default);
    }

    /// <summary>
    /// The effective-head walk Phase 6 needs: follow superseded → superseding transitively and
    /// return the patches nothing supersedes. Depth-capped so a cyclic graph fails the test rather
    /// than hanging the suite — see the cycle characterization above.
    /// </summary>
    private static async Task<List<string>> HeadsOfAsync(
        Npgsql.NpgsqlConnection conn, string vendorId)
    {
        await using var cmd = new Npgsql.NpgsqlCommand(@"
WITH RECURSIVE chain(id, depth) AS (
    SELECT p.id, 0 FROM patches p WHERE p.vendor_id = @vendor_id
    UNION ALL
    SELECT ps.superseded_by_patch_id, chain.depth + 1
    FROM chain JOIN patch_supersedence ps ON ps.patch_id = chain.id
    WHERE chain.depth < 32
)
SELECT DISTINCT p.vendor_id
FROM chain JOIN patches p ON p.id = chain.id
WHERE NOT EXISTS (SELECT 1 FROM patch_supersedence ps WHERE ps.patch_id = chain.id);", conn);
        cmd.Parameters.AddWithValue("vendor_id", vendorId);

        var heads = new List<string>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            heads.Add(reader.GetString(0));
        return heads;
    }
}
