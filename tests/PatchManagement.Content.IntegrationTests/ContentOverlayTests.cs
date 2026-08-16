using Npgsql;
using PatchManagement.Content.Ingestion;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// Phase 5 exit criterion (e): <b>overlays (KEV/EPSS) never insert an advisory and never clobber a
/// publisher's re-sync</b>.
///
/// <para>KEV and EPSS assert things ABOUT a CVE — that it is known-exploited, that it has this
/// exploitation probability — but publish no advisory of their own. The frozen
/// <c>ck_advisories_source</c> excludes them for that reason: admitting them as publishers would
/// let one CVE exist as three rows with divergent scores under <c>UNIQUE (source, external_id)</c>,
/// while the provenance design assumes one merged row carrying several entries.</para>
///
/// <para>The dangerous direction is the other one, and it is not enforced by any constraint: the
/// publisher's own upsert runs far more often than the overlays and could quietly reset their
/// columns to "not evaluated" on every refresh. Nothing in the schema prevents that — only the
/// column list in <c>UpsertAdvisoryAsync</c>'s DO UPDATE does, which is exactly the kind of
/// invariant that survives review and dies to an autocomplete.</para>
/// </summary>
[Collection(ContentPostgresCollection.Name)]
public sealed class ContentOverlayTests(ContentPostgresFixture fx)
{
    private readonly ContentStore _store = new();

    /// <summary>
    /// The criterion's hard half. NVD re-syncs hourly; KEV and EPSS do not. If the publisher upsert
    /// touched <c>kev_*</c>/<c>epss_*</c>, a CVE would be known-exploited for an hour and then
    /// silently revert to "never evaluated" — and Phase 7 would drop its risk score accordingly,
    /// with nothing in any log to say why.
    /// </summary>
    [Fact]
    public async Task A_publisher_resync_does_not_reset_an_applied_overlay()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var id = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, cve), default));
        await Catalogue.CommittedAsync(conn, tx => _store.ApplyKevAsync(conn, tx, Kev(cve), default));
        await Catalogue.CommittedAsync(conn, tx => _store.ApplyEpssAsync(conn, tx, Epss(cve), default));

        await Catalogue.CommittedAsync(conn, tx => _store.UpsertAdvisoryAsync(
            conn, tx, Catalogue.Advisory(Feeds.Nvd, cve, title: "revised", severity: "critical"),
            default));

        Assert.Equal(true, await Catalogue.AdvisoryFieldAsync(conn, id, "kev_listed"));
        Assert.Equal(true, await Catalogue.AdvisoryFieldAsync(conn, id, "kev_known_ransomware_use"));
        Assert.Equal(0.94321, await Catalogue.AdvisoryFieldAsync(conn, id, "epss_score"));

        // The publisher's own fields DID move — otherwise this test would pass against a store
        // whose upsert had stopped updating anything at all.
        Assert.Equal("critical", await Catalogue.AdvisoryFieldAsync(conn, id, "severity"));
    }

    /// <summary>
    /// KEV is a list of CVEs, not of advisories, and the feeds do not arrive in any guaranteed
    /// order. An overlay for a CVE nobody has published yet must enrich nothing and — above all —
    /// insert nothing: a fabricated advisory row would carry no title, no severity and no
    /// publisher, and would satisfy a Phase 6 correlation as though it were real content.
    /// </summary>
    [Fact]
    public async Task An_overlay_for_an_unpublished_cve_enriches_nothing_and_inserts_nothing()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var kevRows = await Catalogue.CommittedAsync(
            conn, tx => _store.ApplyKevAsync(conn, tx, Kev(cve), default));
        var epssRows = await Catalogue.CommittedAsync(
            conn, tx => _store.ApplyEpssAsync(conn, tx, Epss(cve), default));

        Assert.Equal(0, kevRows);
        Assert.Equal(0, epssRows);
        Assert.Equal(0, await Catalogue.CountAdvisoriesAsync(conn, cve));
    }

    /// <summary>
    /// And it self-heals: once the publisher catches up, the next overlay run enriches the row. The
    /// zero above is therefore a deferral, not a loss — which is what makes returning 0 an honest
    /// answer rather than a swallowed failure.
    /// </summary>
    [Fact]
    public async Task An_overlay_that_arrived_early_applies_on_the_next_run()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        Assert.Equal(0, await Catalogue.CommittedAsync(
            conn, tx => _store.ApplyKevAsync(conn, tx, Kev(cve), default)));

        var id = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, cve), default));

        Assert.Equal(1, await Catalogue.CommittedAsync(
            conn, tx => _store.ApplyKevAsync(conn, tx, Kev(cve), default)));
        Assert.Equal(true, await Catalogue.AdvisoryFieldAsync(conn, id, "kev_listed"));
    }

    /// <summary>
    /// One CVE legitimately exists under several publishers — NVD describes it, MSRC ships the
    /// Windows fix for it. KEV asserts a fact about the CVE, so it must reach every row carrying
    /// that id; enriching only the first would leave the Windows-side advisory looking un-exploited.
    /// </summary>
    [Fact]
    public async Task An_overlay_reaches_every_publisher_carrying_the_same_cve()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var fromNvd = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, cve), default));
        var fromMsrc = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Msrc, cve), default));

        var enriched = await Catalogue.CommittedAsync(
            conn, tx => _store.ApplyKevAsync(conn, tx, Kev(cve), default));

        Assert.Equal(2, enriched);
        Assert.Equal(true, await Catalogue.AdvisoryFieldAsync(conn, fromNvd, "kev_listed"));
        Assert.Equal(true, await Catalogue.AdvisoryFieldAsync(conn, fromMsrc, "kev_listed"));
    }

    /// <summary>
    /// EPSS scores are probabilities in [0,1]. A connector that read a percentage and forgot to
    /// divide would inflate every Phase 7 score by two orders of magnitude, and — because the value
    /// is plausible-looking — nothing downstream would notice. The CHECK must reject it at ingest.
    /// </summary>
    [Fact]
    public async Task An_epss_score_expressed_as_a_percentage_is_rejected_rather_than_stored()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, cve), default));

        var percentage = Epss(cve) with { Score = 94.321, Percentile = 99.876 };

        var ex = await Assert.ThrowsAsync<PostgresException>(() => Catalogue.CommittedAsync(
            conn, tx => _store.ApplyEpssAsync(conn, tx, percentage, default)));

        Assert.Equal("23514", ex.SqlState); // check_violation
    }

    /// <summary>
    /// CHARACTERIZATION — this pins a REAL GAP, not a guarantee. Read the assertion as a statement
    /// of what the module currently cannot do.
    ///
    /// <para><c>advisories.kev_listed</c> is deliberately three-valued (ContentCatalogueTests):
    /// NULL = the KEV feed has not been evaluated for this CVE, false = evaluated and absent,
    /// true = listed. The distinction exists so Phase 7 cannot weight a never-run sync as a
    /// confirmed absence (HARD-PROBLEMS #8).</para>
    ///
    /// <para><b>The ingestion path can only ever write <c>true</c>.</b> <c>ApplyKevAsync</c> sets
    /// <c>kev_listed = true</c> and nothing in <see cref="Content.Abstractions.IContentStore"/>
    /// writes <c>false</c>, so after a complete, successful KEV sync every CVE that is NOT
    /// known-exploited remains NULL — indistinguishable from a catalogue where KEV never ran. The
    /// middle value is unreachable, and the column is two-valued in practice.</para>
    ///
    /// <para>Not fixed here: the fix is a sweep that marks the complement of the feed, which needs
    /// a decision about what "the complement" means for a partial or failed KEV run — a KEV that
    /// fetched half its list must not mark the other half as absent. Recorded as <b>D-502</b>,
    /// owner Phase 7, which is the consumer that would be misled.</para>
    /// </summary>
    [Fact]
    public async Task A_kev_sync_cannot_currently_record_evaluated_and_absent()
    {
        await using var conn = await fx.OpenAsync();
        var listed = $"CVE-2026-{Catalogue.Uid()}";
        var notListed = $"CVE-2026-{Catalogue.Uid()}";

        var listedId = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, listed), default));
        var notListedId = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, notListed), default));

        // A complete KEV run: it carries `listed` and, correctly, says nothing about `notListed`.
        await Catalogue.CommittedAsync(conn, tx => _store.ApplyKevAsync(conn, tx, Kev(listed), default));

        Assert.Equal(true, await Catalogue.AdvisoryFieldAsync(conn, listedId, "kev_listed"));

        // The gap. This SHOULD be false — "KEV ran, and this CVE is not on the list". It is NULL,
        // which the schema defines as "KEV has not been evaluated for this CVE at all".
        Assert.Null(await Catalogue.AdvisoryFieldAsync(conn, notListedId, "kev_listed"));
    }

    // -----------------------------------------------------------------------------------------

    private static KevOverlay Kev(string cve) =>
        new(cve,
            DateAdded: new DateOnly(2026, 7, 1),
            DueDate: new DateOnly(2026, 7, 22),
            KnownRansomwareUse: true,
            Provenance: Catalogue.Prov(Feeds.Kev));

    private static EpssOverlay Epss(string cve) =>
        new(cve,
            Score: 0.94321,
            Percentile: 0.99876,
            ScoredAt: DateTimeOffset.Parse("2026-07-28T00:00:00Z"),
            Provenance: Catalogue.Prov(Feeds.Epss));
}
