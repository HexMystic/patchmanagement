using PatchManagement.Content.Abstractions;
using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// Phase 5 exit criterion (b), the half that was missing: a cursor is not merely computed and
/// persisted, it is <b>sent</b>.
///
/// <para>Until this file existed, every connector emitted a cursor and <c>ContentSyncService</c>
/// stored it, but no <c>SyncAsync</c> ever read <c>state.Cursor</c> — so refresh was idempotent and
/// not incremental, and each run re-fetched the same window. <c>docs/phases/phase-5.md</c> recorded
/// that as <i>"incrementality is emitted but never consumed"</i>.</para>
///
/// <para><b>Every assertion here is about the REQUEST, not the batch.</b> A connector that reads the
/// cursor, computes a window and then throws it away returns a perfectly plausible batch; only the
/// outgoing URI, the outgoing validators, or the work not done can distinguish the two. Same
/// standard as NEVER #3.</para>
///
/// <para><b>The eight feeds do not share one mechanism, and pretending otherwise is what ADR 0022
/// warned against</b> (<i>"the slice must restate the cursor contract, not paper over it"</i>). Four
/// families:</para>
/// <list type="bullet">
///   <item><b>Server-side window</b> — <c>nvd</c> (<c>lastModStartDate</c>), <c>rhsa</c>
///     (<c>after</c>). The feed documents a filter parameter; the cursor becomes that parameter.</item>
///   <item><b>Conditional GET</b> — <c>kev</c>, <c>usn</c>. A whole file with no filter parameter,
///     but a host that serves HTTP validators. The cursor carries them and a 304 ends the run.</item>
///   <item><b>Client-side cutoff</b> — <c>epss</c>, <c>dsa</c>. No filter parameter and no usable
///     validator (ADR 0022 records that salsa's raw-git URL has no conditional-GET story). The
///     cursor bounds the parse, which bounds what is written.</item>
///   <item><b>Local catalogue</b> — <c>wsusscn2</c>. No network at all; the cursor is the cab's
///     <c>PackageId</c> and an unchanged one skips the shard walk.</item>
/// </list>
///
/// <para>Inventing a query parameter for the third and fourth families would have repeated this
/// module's own recurring defect — a request written against a shape no server produces.</para>
/// </summary>
public sealed class IncrementalSyncTests
{
    private static readonly DateTimeOffset RetrievedAt = new(2026, 8, 25, 12, 0, 0, TimeSpan.Zero);

    private static ContentSourceState State(string? cursor, string? endpoint = null) =>
        new("default", endpoint, cursor);

    /// <summary>Reads one query parameter off a recorded request, decoded.</summary>
    private static string? QueryValue(Uri uri, string name)
    {
        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var split = pair.Split('=', 2);
            if (Uri.UnescapeDataString(split[0]) == name)
                return split.Length > 1 ? Uri.UnescapeDataString(split[1]) : string.Empty;
        }

        return null;
    }

    // ---------------------------------------------------------------- nvd

    /// <summary>
    /// The cursor becomes NVD's own incremental parameter. <c>NvdConnector</c>'s doc comment once
    /// claimed "Incremental via <c>lastModStartDate</c>" while never sending it — the claim was
    /// struck rather than made true, and this is the test that makes it true.
    /// </summary>
    [Fact]
    public async Task Nvd_sends_its_cursor_as_lastModStartDate()
    {
        var fetcher = new FakeContentFetcher(Samples.Nvd("CVE-2021-44228"));
        var cursor = new DateTimeOffset(2026, 6, 17, 4, 12, 5, 460, TimeSpan.Zero).ToString("O");

        await new NvdConnector(fetcher).SyncAsync(State(cursor), CancellationToken.None);

        Assert.Equal("2026-06-17T04:12:05.460Z", QueryValue(fetcher.LastRequest, "lastModStartDate"));
    }

    /// <summary>
    /// NVD rejects <c>lastModStartDate</c> unless <c>lastModEndDate</c> accompanies it, so sending
    /// one without the other would turn every incremental run into a 404 — incrementality that
    /// fails closed on the first scheduled sync after release.
    /// </summary>
    [Fact]
    public async Task Nvd_pairs_the_window_with_an_end_date()
    {
        var fetcher = new FakeContentFetcher(Samples.Nvd("CVE-2021-44228"));

        await new NvdConnector(fetcher).SyncAsync(State("2026-06-17T04:12:05.4600000+00:00"), CancellationToken.None);

        Assert.NotNull(QueryValue(fetcher.LastRequest, "lastModEndDate"));
    }

    /// <summary>
    /// A first run has no cursor and must ask for everything. Defaulting to "now" would make an
    /// empty catalogue permanent: every run would request a window starting after the last record
    /// it never ingested.
    /// </summary>
    [Fact]
    public async Task Nvd_first_run_requests_no_window()
    {
        var fetcher = new FakeContentFetcher(Samples.Nvd("CVE-2021-44228"));

        await new NvdConnector(fetcher).SyncAsync(State(cursor: null), CancellationToken.None);

        Assert.Null(QueryValue(fetcher.LastRequest, "lastModStartDate"));
    }

    /// <summary>
    /// The second silent-truncation path, recorded alongside the cursor gap: <c>startIndex</c>,
    /// <c>totalResults</c> and <c>resultsPerPage</c> were never read, so a response spanning more
    /// than one page was truncated to the first and reported <c>ok</c>.
    ///
    /// <para>The two pages are composed from two REAL captures — every CVE record is byte-for-byte
    /// what NVD served — with only the paging counters set to describe that composition. A
    /// hand-written envelope is exactly what this module keeps having to delete.</para>
    /// </summary>
    [Fact]
    public async Task Nvd_follows_pagination_to_the_last_page()
    {
        var fetcher = new FakeContentFetcher(
            NvdPage(Samples.Nvd("CVE-2021-44228"), startIndex: 0, total: 2),
            NvdPage(Samples.Nvd("CVE-2015-5477"), startIndex: 1, total: 2));

        var batch = await new NvdConnector(fetcher).SyncAsync(State(cursor: null), CancellationToken.None);

        Assert.Equal(2, fetcher.Requests.Count);
        Assert.Equal("1", QueryValue(fetcher.Requests[1], "startIndex"));
        Assert.Equal(2, batch.Advisories.Count);
    }

    /// <summary>Rewrites only the paging counters on a real capture; the records are untouched.</summary>
    private static string NvdPage(string capture, int startIndex, int total)
    {
        var node = System.Text.Json.Nodes.JsonNode.Parse(capture)!.AsObject();
        node["startIndex"] = startIndex;
        node["totalResults"] = total;
        node["resultsPerPage"] = 1;
        return node.ToJsonString();
    }

    // --------------------------------------------------------------- rhsa

    /// <summary>
    /// Red Hat's securitydata API filters server-side on <c>after</c>, at date granularity. The
    /// cursor is a full timestamp, so the date half is what goes on the wire.
    /// </summary>
    [Fact]
    public async Task Rhsa_sends_its_cursor_as_the_after_parameter()
    {
        var fetcher = new FakeContentFetcher(Samples.Rhsa());

        await new RhsaConnector(fetcher).SyncAsync(State("2026-08-20T14:30:00.0000000+00:00"), CancellationToken.None);

        Assert.Equal("2026-08-20", QueryValue(fetcher.LastRequest, "after"));
    }

    /// <summary>A first run must not bound the window it has never read.</summary>
    [Fact]
    public async Task Rhsa_first_run_sends_no_after_parameter()
    {
        var fetcher = new FakeContentFetcher(Samples.Rhsa());

        await new RhsaConnector(fetcher).SyncAsync(State(cursor: null), CancellationToken.None);

        Assert.Null(QueryValue(fetcher.LastRequest, "after"));
    }

    // --------------------------------------------------------------- msrc

    /// <summary>
    /// MSRC publishes one document per month and the index lists all 191 of them. The cursor names
    /// the last month ingested, so a sync fetches only the months after it — the index request plus
    /// one document, not the index plus everything.
    /// </summary>
    [Fact]
    public async Task Msrc_fetches_only_the_months_after_its_cursor()
    {
        var fetcher = new FakeContentFetcher(Samples.MsrcUpdates(), Samples.Msrc());

        await new MsrcConnector(fetcher).SyncAsync(State("2026-Jul"), CancellationToken.None);

        Assert.Equal(2, fetcher.Requests.Count);
        Assert.EndsWith("2026-Aug", fetcher.LastRequest.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A cursor already on the newest month means there is nothing to fetch. The index still has to
    /// be read — that is how "nothing new" is established — but no document is pulled, and the
    /// cursor is handed back unchanged so the next run resumes from the same place.
    /// </summary>
    [Fact]
    public async Task Msrc_fetches_no_document_when_its_cursor_is_the_newest_month()
    {
        var fetcher = new FakeContentFetcher(Samples.MsrcUpdates());

        var batch = await new MsrcConnector(fetcher).SyncAsync(State("2026-Aug"), CancellationToken.None);

        Assert.Single(fetcher.Requests);
        Assert.Empty(batch.Patches);
        Assert.Equal("2026-Aug", batch.Cursor);
    }

    // ---------------------------------------------------------------- kev

    /// <summary>
    /// CISA serves a whole-file catalogue with no filter parameter, so the cursor reaches the feed
    /// as HTTP validators. The stored ETag must arrive as <c>If-None-Match</c>.
    /// </summary>
    [Fact]
    public async Task Kev_sends_its_stored_validators_on_a_conditional_get()
    {
        var fetcher = new FakeContentFetcher(Samples.Kev());
        var stored = new FeedCursor("2026.07.27", "\"kev-etag-1\"", new DateTimeOffset(2026, 7, 27, 19, 0, 0, TimeSpan.Zero));

        await new KevConnector(fetcher).SyncAsync(State(stored.Format()), CancellationToken.None);

        var sent = Assert.Single(fetcher.Conditionals);
        Assert.Equal("\"kev-etag-1\"", sent.ETag);
        Assert.Equal(new DateTimeOffset(2026, 7, 27, 19, 0, 0, TimeSpan.Zero), sent.LastModified);
    }

    /// <summary>
    /// A 304 is the server asserting "unchanged". Nothing is written and the cursor is handed back
    /// EXACTLY as stored — validators included — because losing them would silently downgrade every
    /// subsequent run to an unconditional fetch of the whole file.
    ///
    /// <para>This is deliberately not the empty-batch hazard ADR 0022 mitigates. That one infers
    /// absence from a parse that found nothing; this one is told.</para>
    /// </summary>
    [Fact]
    public async Task Kev_holds_its_cursor_and_writes_nothing_when_the_server_says_not_modified()
    {
        var stored = new FeedCursor("2026.07.27", "\"kev-etag-1\"", null).Format();
        var fetcher = new FakeContentFetcher { NotModified = true };

        var batch = await new KevConnector(fetcher).SyncAsync(State(stored), CancellationToken.None);

        Assert.Empty(batch.KevOverlays);
        Assert.Equal(stored, batch.Cursor);
    }

    /// <summary>
    /// A 200 must carry the NEW validators forward, or the conditional request can never fire twice.
    /// </summary>
    [Fact]
    public async Task Kev_persists_the_validators_the_response_carried()
    {
        var fetcher = new FakeContentFetcher(Samples.Kev()) { ResponseETag = "\"kev-etag-2\"" };

        var batch = await new KevConnector(fetcher).SyncAsync(State(cursor: null), CancellationToken.None);

        var persisted = FeedCursor.Read(batch.Cursor);
        Assert.Equal("2026.07.27", persisted.Semantic);
        Assert.Equal("\"kev-etag-2\"", persisted.ETag);
    }

    // ---------------------------------------------------------------- usn

    /// <summary>
    /// The usn-db body is 260&#160;MB. A conditional GET is not a micro-optimisation here: it is what
    /// makes a frequent schedule affordable at all, which is why this feed is in the conditional
    /// family rather than the cutoff one.
    /// </summary>
    [Fact]
    public async Task Usn_sends_its_stored_validators_on_a_conditional_get()
    {
        var fetcher = new FakeContentFetcher(Samples.Usn());
        var stored = new FeedCursor("1782228956.329703", "\"usn-etag-1\"", null);

        await new UsnConnector(fetcher).SyncAsync(State(stored.Format()), CancellationToken.None);

        Assert.Equal("\"usn-etag-1\"", Assert.Single(fetcher.Conditionals).ETag);
    }

    /// <summary>A 304 transfers no body and writes no rows.</summary>
    [Fact]
    public async Task Usn_holds_its_cursor_and_writes_nothing_when_the_server_says_not_modified()
    {
        var stored = new FeedCursor("1782228956.329703", "\"usn-etag-1\"", null).Format();
        var fetcher = new FakeContentFetcher { NotModified = true };

        var batch = await new UsnConnector(fetcher).SyncAsync(State(stored), CancellationToken.None);

        Assert.Empty(batch.Advisories);
        Assert.Empty(batch.Patches);
        Assert.Equal(stored, batch.Cursor);
    }

    // ---------------------------------------------------------------- dsa

    /// <summary>
    /// The DSA list is newest-first and salsa offers neither a filter parameter nor a conditional-GET
    /// story (ADR 0022), so the cursor bounds the PARSE. The full id is the resume point precisely
    /// because the file is date-ordered rather than id-ordered: a re-issued old advisory is
    /// re-inserted at the top and is therefore picked up, not skipped.
    /// </summary>
    [Fact]
    public async Task Dsa_stops_parsing_at_the_advisory_its_cursor_names()
    {
        var fetcher = new FakeContentFetcher(Samples.Dsa());

        var batch = await new DebianDsaConnector(fetcher).SyncAsync(State("DSA-6453-1"), CancellationToken.None);

        Assert.Equal(["DSA-6455-1", "DSA-6454-1"], batch.Advisories.Select(a => a.ExternalId));
    }

    /// <summary>
    /// The cursor still advances to the newest id seen, not to the one it stopped at — otherwise the
    /// feed would re-read the same two advisories forever.
    /// </summary>
    [Fact]
    public async Task Dsa_advances_its_cursor_to_the_newest_advisory_it_stopped_above()
    {
        var fetcher = new FakeContentFetcher(Samples.Dsa());

        var batch = await new DebianDsaConnector(fetcher).SyncAsync(State("DSA-6453-1"), CancellationToken.None);

        Assert.Equal("DSA-6455-1", batch.Cursor);
    }

    /// <summary>
    /// A cursor naming an id the list no longer carries must degrade to a full parse, not to an
    /// empty one. Debian rewrites this file; an id can vanish. Silently ingesting nothing because
    /// the resume point was not found is the "reports success while untrue" failure again.
    /// </summary>
    [Fact]
    public async Task Dsa_parses_the_whole_list_when_its_cursor_is_no_longer_present()
    {
        var fetcher = new FakeContentFetcher(Samples.Dsa());

        var batch = await new DebianDsaConnector(fetcher).SyncAsync(State("DSA-0000-9"), CancellationToken.None);

        Assert.Equal(6519, batch.Advisories.Count);
    }

    // --------------------------------------------------------------- epss

    /// <summary>
    /// EPSS republishes every score daily and the cursor is the model date. When the date has not
    /// moved, the scores are the ones already applied — re-applying them is hundreds of thousands of
    /// no-op updates per run. The fetch still happens (there is no way to ask FIRST "has the model
    /// moved?"), so the saving is in what is written, and that is what this asserts.
    /// </summary>
    [Fact]
    public async Task Epss_applies_no_overlays_when_the_model_date_has_not_moved()
    {
        var fetcher = new FakeContentFetcher(Samples.Epss());

        var batch = await new EpssConnector(fetcher).SyncAsync(State("2026-07-28"), CancellationToken.None);

        Assert.Empty(batch.EpssOverlays);
        Assert.Equal("2026-07-28", batch.Cursor);
    }

    /// <summary>The other half: a moved model date must apply in full.</summary>
    [Fact]
    public async Task Epss_applies_its_overlays_when_the_model_date_has_moved()
    {
        var fetcher = new FakeContentFetcher(Samples.Epss());

        var batch = await new EpssConnector(fetcher).SyncAsync(State("2026-07-27"), CancellationToken.None);

        Assert.NotEmpty(batch.EpssOverlays);
    }

    // ----------------------------------------------------------- wsusscn2

    /// <summary>
    /// wsusscn2 reads a LOCAL cab, so there is no request to put a cursor on. Its cursor is the
    /// catalogue's <c>PackageId</c>, and an unchanged one means the graph walk — 115&#160;MB of XML
    /// and a shard lookup per update — can be skipped entirely.
    ///
    /// <para>Asserted through <c>Requested</c>: the evidence that the walk did not happen is that no
    /// revision was ever looked up. An empty batch alone would not distinguish "skipped" from
    /// "walked and found nothing", and the latter is a format change this module throws on.</para>
    /// </summary>
    [Fact]
    public async Task Wsusscn2_skips_the_catalogue_walk_when_the_package_id_is_unchanged()
    {
        var source = new FakeWsusCatalogSource();
        var connector = new Wsusscn2Connector(_ => source);

        var batch = await connector.SyncAsync(
            State("e1a000e0-066b-497a-ba62-246d4af43e55", endpoint: "/lab/wsusscn2.cab"),
            CancellationToken.None);

        Assert.Empty(source.Requested);
        Assert.Empty(batch.Patches);
        Assert.Equal("e1a000e0-066b-497a-ba62-246d4af43e55", batch.Cursor);
    }

    /// <summary>A different PackageId is a new catalogue and must be walked in full.</summary>
    [Fact]
    public async Task Wsusscn2_walks_the_catalogue_when_the_package_id_has_changed()
    {
        var source = new FakeWsusCatalogSource();
        var connector = new Wsusscn2Connector(_ => source);

        var batch = await connector.SyncAsync(
            State("a-previous-package-id", endpoint: "/lab/wsusscn2.cab"),
            CancellationToken.None);

        Assert.NotEmpty(source.Requested);
        Assert.NotEmpty(batch.Patches);
    }
}
