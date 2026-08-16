using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using PatchManagement.Content.Ingestion;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// The orchestration guarantees criteria (c) and (f) actually rest on: one feed is applied
/// atomically, and a failure is recorded honestly instead of being rounded up to success.
///
/// <para>Idempotence at the store level is worth nothing if a failed run can leave half a batch
/// behind — the next run would re-present the whole window and upsert onto a partial state whose
/// missing rows nobody recorded. So "the same payload twice writes the same rows" needs "a payload
/// that failed wrote NO rows" underneath it.</para>
///
/// <para><b>These do not tick criterion (b).</b> They prove the cursor advances on success and
/// holds on failure, which is half of what (b) asks. The other half — that the cursor is actually
/// SENT to the feed — is unimplemented: no connector reads <c>state.Cursor</c> (phase-5.md). Refresh
/// is idempotent but not incremental, and (b) stays unticked for that reason rather than for want
/// of a test.</para>
/// </summary>
[Collection(ContentPostgresCollection.Name)]
public sealed class ContentSyncServiceTests(ContentPostgresFixture fx)
{
    private readonly ContentStore _store = new();

    /// <summary>
    /// The atomicity guarantee, forced with a record the database refuses: a good advisory FIRST,
    /// then one carrying a severity outside the frozen vocabulary. The good row is written and
    /// visible inside the transaction, so only a real rollback removes it.
    /// </summary>
    [Fact]
    public async Task A_record_the_database_refuses_rolls_back_every_record_beside_it()
    {
        var good = $"CVE-2026-{Catalogue.Uid()}";
        var poisoned = $"CVE-2026-{Catalogue.Uid()}";

        var batch = new NormalizedBatch
        {
            Advisories =
            [
                Catalogue.Advisory(Feeds.Nvd, good),
                Catalogue.Advisory(Feeds.Nvd, poisoned, severity: "catastrophic"),
            ],
            Cursor = "should-not-be-persisted",
        };

        var outcome = await RunAsync(batch, $"nvd-{Catalogue.Uid()}");

        Assert.Equal(SyncOutcome.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);

        await using var conn = await fx.OpenAsync();
        Assert.Equal(0, await Catalogue.CountAdvisoriesAsync(conn, good));
        Assert.Equal(0, await Catalogue.CountAdvisoriesAsync(conn, poisoned));
    }

    /// <summary>
    /// A failed run must not advance the bookmark past data it never read. If it did, the next run
    /// would resume after the gap and the missed window would never be fetched again — a permanent
    /// hole in the catalogue that no error surfaces, because the failure has already scrolled away.
    /// </summary>
    [Fact]
    public async Task A_failed_sync_holds_the_cursor_and_records_the_failure_on_the_feed_row()
    {
        var instance = $"nvd-{Catalogue.Uid()}";

        var first = await RunAsync(
            new NormalizedBatch { Cursor = "2026-07-01T00:00:00Z" }, instance);
        Assert.Equal(SyncOutcome.Ok, first.Status);

        var failed = await RunAsync(
            new NormalizedBatch { Cursor = "2026-07-29T00:00:00Z" }, instance,
            throws: new HttpRequestException("the feed returned 503"));

        Assert.Equal(SyncOutcome.Failed, failed.Status);
        Assert.Equal("2026-07-01T00:00:00Z", failed.Cursor);

        await using var conn = await fx.OpenAsync();
        Assert.Equal("2026-07-01T00:00:00Z", await _store.GetCursorAsync(conn, Feeds.Nvd, instance, default));
        Assert.Equal("failed", await FeedFieldAsync(conn, instance, "last_status"));
        Assert.NotNull(await FeedFieldAsync(conn, instance, "last_error"));
    }

    /// <summary>
    /// The success path closes the loop: the cursor a run returns is the cursor the NEXT run's
    /// connector is handed. Asserted on what the connector actually observed, because persisting a
    /// cursor nothing reads back is exactly the state the module is in today for incrementality.
    /// </summary>
    [Fact]
    public async Task A_successful_sync_advances_the_cursor_and_hands_it_to_the_next_run()
    {
        var instance = $"nvd-{Catalogue.Uid()}";

        await RunAsync(new NormalizedBatch { Cursor = "2026-07-29T00:00:00Z" }, instance);

        var second = new ScriptedConnector(Feeds.Nvd, NormalizedBatch.Empty);
        await ServiceAsync().RunAsync(second, instance, endpoint: null, default);

        Assert.Equal("2026-07-29T00:00:00Z", second.ObservedState?.Cursor);
    }

    /// <summary>
    /// The counts a successful sync reports must describe what it wrote. An operator reading
    /// "ok, 0 advisories" against a feed of thousands is the one signal that would reveal the
    /// rhsa-shaped defect recorded in phase-5.md, where a wrong envelope yields an empty batch and
    /// a green status.
    /// </summary>
    [Fact]
    public async Task A_successful_sync_reports_the_counts_it_actually_wrote()
    {
        var cve = $"CVE-2026-{Catalogue.Uid()}";
        var kb = $"KB{Catalogue.Uid()}";

        // MSRC is the one feed that publishes both halves — an advisory and the KB that fixes it —
        // so a single batch can exercise every counter without an incoherent fixture.
        var batch = new NormalizedBatch
        {
            Advisories =
            [
                Catalogue.Advisory(Feeds.Msrc, cve, affects:
                [
                    Catalogue.Affect("windows", Ecosystems.Windows, "windows:10.0.19045", "10.0.19045.4046"),
                    Catalogue.Affect("windows", Ecosystems.Windows, "windows:10.0.22631", "10.0.22631.3155"),
                ]),
            ],
            Patches = [Catalogue.Patch(Feeds.Msrc, kb)],
            KevOverlays =
            [
                new(cve, new DateOnly(2026, 7, 1), new DateOnly(2026, 7, 22), true,
                    Catalogue.Prov(Feeds.Kev)),
            ],
        };

        var outcome = await RunAsync(batch, $"msrc-{Catalogue.Uid()}", kind: Feeds.Msrc);

        Assert.Equal(SyncOutcome.Ok, outcome.Status);
        Assert.Equal(1, outcome.AdvisoriesUpserted);
        Assert.Equal(2, outcome.AffectsUpserted);
        Assert.Equal(1, outcome.PatchesUpserted);
        Assert.Equal(1, outcome.OverlaysApplied);
    }

    // -----------------------------------------------------------------------------------------

    private ContentSyncService ServiceAsync() =>
        new(_store, new FixtureConnectionFactory(fx), NullLogger<ContentSyncService>.Instance);

    private Task<SyncOutcome> RunAsync(
        NormalizedBatch batch, string instance, Exception? throws = null, string kind = Feeds.Nvd) =>
        ServiceAsync().RunAsync(
            new ScriptedConnector(kind, batch, throws), instance, endpoint: null, default);

    private static async Task<object?> FeedFieldAsync(
        NpgsqlConnection conn, string instance, string column)
    {
        await using var cmd = new NpgsqlCommand(
            $"SELECT {column} FROM content_sources WHERE instance = @i", conn);
        cmd.Parameters.AddWithValue("i", instance);
        var value = await cmd.ExecuteScalarAsync();
        return value is DBNull ? null : value;
    }
}
