using PatchManagement.Content.Ingestion;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// Phase 5 exit criterion (c): <b>refresh is idempotent — the same payload twice writes the same
/// rows</b>.
///
/// <para>This is the criterion the whole ingestion design rests on, because no feed is incremental
/// yet (phase-5.md: no connector reads <c>state.Cursor</c>). Every refresh therefore re-presents
/// the entire window, and a single non-idempotent write would grow the catalogue without bound on
/// a schedule.</para>
///
/// <para><c>ContentCatalogueTests</c> proves the <em>constraints</em> reject a duplicate by raising
/// 23505. These prove the <em>store</em> never provokes one: it must resolve to an UPDATE, keep the
/// row identity stable, and apply the newer values. A test that only counted rows would pass for a
/// store that threw the second time and swallowed it.</para>
/// </summary>
[Collection(ContentPostgresCollection.Name)]
public sealed class ContentIdempotencyTests(ContentPostgresFixture fx)
{
    private readonly ContentStore _store = new();

    [Fact]
    public async Task Re_ingesting_an_advisory_updates_the_same_row_rather_than_inserting_a_second()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var first = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, cve), default));
        var second = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, cve), default));

        Assert.Equal(1, await Catalogue.CountAdvisoriesAsync(conn, cve));

        // The id must be STABLE, not merely unduplicated. advisory_affects and findings both
        // reference it, so a store that deleted and reinserted would silently orphan them.
        Assert.Equal(first, second);
    }

    /// <summary>
    /// The second run carries corrected values — which is the normal case, since a publisher
    /// revises severity and CVSS after the initial disclosure. The row must adopt them.
    /// </summary>
    [Fact]
    public async Task A_re_ingest_applies_the_newer_values_instead_of_keeping_the_first_ones()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var id = await Catalogue.CommittedAsync(conn, tx => _store.UpsertAdvisoryAsync(
            conn, tx, Catalogue.Advisory(Feeds.Nvd, cve, severity: "medium", cvss: 5.3), default));

        await Catalogue.CommittedAsync(conn, tx => _store.UpsertAdvisoryAsync(
            conn, tx,
            Catalogue.Advisory(Feeds.Nvd, cve, title: "revised", severity: "critical", cvss: 9.8),
            default));

        Assert.Equal("critical", await Catalogue.AdvisoryFieldAsync(conn, id, "severity"));
        Assert.Equal(9.8, await Catalogue.AdvisoryFieldAsync(conn, id, "cvss_base_score"));
        Assert.Equal("revised", await Catalogue.AdvisoryFieldAsync(conn, id, "title"));
    }

    /// <summary>
    /// The real USN-8465-1 shape, which is in the committed fixture for exactly this reason: one
    /// package fixed at a DIFFERENT version on each of three releases. Re-ingesting must leave
    /// three rows carrying three versions — a store keyed without <c>platform</c> would collapse
    /// them to one and silently lose two releases' remediation.
    /// </summary>
    [Fact]
    public async Task Re_ingesting_a_multi_release_advisory_keeps_one_row_per_release()
    {
        await using var conn = await fx.OpenAsync();
        var usn = $"USN-{Catalogue.Uid()}-1";

        NormalizedAffect[] affects =
        [
            Catalogue.Affect("mina2", Ecosystems.Deb, "ubuntu:22.04", "2.1.5-1ubuntu0.1~esm1"),
            Catalogue.Affect("mina2", Ecosystems.Deb, "ubuntu:24.04", "2.2.1-3ubuntu0.1~esm1"),
            Catalogue.Affect("mina2", Ecosystems.Deb, "ubuntu:26.04", "2.2.1-4ubuntu0.1~esm1"),
        ];

        var id = await IngestAsync(conn, Catalogue.Advisory(Feeds.Usn, usn, affects: affects));
        Assert.Equal(3, await Catalogue.CountAffectsAsync(conn, id));

        await IngestAsync(conn, Catalogue.Advisory(Feeds.Usn, usn, affects: affects));
        Assert.Equal(3, await Catalogue.CountAffectsAsync(conn, id));

        // And the versions survived — a count alone would pass while every value was wrong.
        Assert.Equal(
            new[] { "2.1.5-1ubuntu0.1~esm1", "2.2.1-3ubuntu0.1~esm1", "2.2.1-4ubuntu0.1~esm1" },
            await FixedVersionsAsync(conn, id));
    }

    /// <summary>
    /// The NVD-CPE case: no release scope, so <c>platform</c> is NULL. Under PostgreSQL's DEFAULT
    /// null-distinct semantics the ON CONFLICT arbiter would not match the existing row and the
    /// second write would INSERT — one duplicate per refresh, forever. Only the
    /// <c>NULLS NOT DISTINCT</c> index makes this an UPDATE, and only this test proves the store's
    /// arbiter actually resolves to that index.
    /// </summary>
    [Fact]
    public async Task A_fix_statement_with_no_platform_is_updated_rather_than_duplicated()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var id = await IngestAsync(conn, Catalogue.Advisory(
            Feeds.Nvd, cve,
            affects: [Catalogue.Affect("openssl", Ecosystems.Deb, platform: null, "3.0.2")]));

        await IngestAsync(conn, Catalogue.Advisory(
            Feeds.Nvd, cve,
            affects: [Catalogue.Affect("openssl", Ecosystems.Deb, platform: null, "3.0.14")]));

        Assert.Equal(1, await Catalogue.CountAffectsAsync(conn, id));
        Assert.Equal(new[] { "3.0.14" }, await FixedVersionsAsync(conn, id));
    }

    [Fact]
    public async Task Re_ingesting_a_patch_updates_the_same_row_rather_than_inserting_a_second()
    {
        await using var conn = await fx.OpenAsync();
        var kb = $"KB{Catalogue.Uid()}";

        var first = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertPatchAsync(conn, tx, Catalogue.Patch(Feeds.Msrc, kb), default));
        var second = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertPatchAsync(
                conn, tx, Catalogue.Patch(Feeds.Msrc, kb, title: "revised", reversible: true), default));

        Assert.Equal(first, second);
        Assert.Equal("revised", await Catalogue.PatchFieldAsync(conn, first, "title"));
        Assert.Equal(true, await Catalogue.PatchFieldAsync(conn, first, "reversible"));
    }

    /// <summary>
    /// <c>EnsureSourceAsync</c> runs at the head of EVERY sync, so it is the single most frequently
    /// repeated write in the module. It must never accumulate feed rows.
    /// </summary>
    [Fact]
    public async Task Registering_a_feed_twice_leaves_one_row_and_refreshes_its_endpoint()
    {
        await using var conn = await fx.OpenAsync();
        var instance = $"rhel-9-{Catalogue.Uid()}";

        await _store.EnsureSourceAsync(conn, Feeds.Rhsa, instance, "https://example.invalid/a", default);
        await _store.EnsureSourceAsync(conn, Feeds.Rhsa, instance, "https://example.invalid/b", default);

        await using var cmd = new Npgsql.NpgsqlCommand(
            "SELECT count(*), min(endpoint) FROM content_sources WHERE kind = @k AND instance = @i", conn);
        cmd.Parameters.AddWithValue("k", Feeds.Rhsa);
        cmd.Parameters.AddWithValue("i", instance);
        await using var reader = await cmd.ExecuteReaderAsync();
        await reader.ReadAsync();

        Assert.Equal(1, reader.GetInt64(0));
        Assert.Equal("https://example.invalid/b", reader.GetString(1));
    }

    /// <summary>
    /// A cursor is only worth persisting if it comes back. This closes the loop
    /// <c>ContentSyncService</c> depends on for its hold-on-failure behaviour.
    /// </summary>
    [Fact]
    public async Task A_persisted_cursor_is_returned_on_the_next_run()
    {
        await using var conn = await fx.OpenAsync();
        var instance = $"nvd-{Catalogue.Uid()}";

        await _store.EnsureSourceAsync(conn, Feeds.Nvd, instance, endpoint: null, default);
        Assert.Null(await _store.GetCursorAsync(conn, Feeds.Nvd, instance, default));

        await _store.UpdateSyncStatusAsync(
            conn, Feeds.Nvd, instance, "2026-07-29T00:00:00Z", "ok", error: null, default);

        Assert.Equal(
            "2026-07-29T00:00:00Z", await _store.GetCursorAsync(conn, Feeds.Nvd, instance, default));
    }

    // -----------------------------------------------------------------------------------------

    private async Task<Guid> IngestAsync(Npgsql.NpgsqlConnection conn, NormalizedAdvisory advisory) =>
        await Catalogue.CommittedAsync(conn, async tx =>
        {
            var id = await _store.UpsertAdvisoryAsync(conn, tx, advisory, default);
            foreach (var affect in advisory.Affects)
                await _store.UpsertAffectAsync(conn, tx, id, affect, default);
            return id;
        });

    private static async Task<List<string>> FixedVersionsAsync(
        Npgsql.NpgsqlConnection conn, Guid advisoryId)
    {
        await using var cmd = new Npgsql.NpgsqlCommand(
            "SELECT fixed_version FROM advisory_affects WHERE advisory_id = @id ORDER BY fixed_version",
            conn);
        cmd.Parameters.AddWithValue("id", advisoryId);

        var versions = new List<string>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            versions.Add(reader.GetString(0));
        return versions;
    }
}
