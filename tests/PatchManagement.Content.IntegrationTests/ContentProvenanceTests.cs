using PatchManagement.Content.Ingestion;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// Phase 5 exit criterion (d): <b>provenance is recorded per record, non-empty, and MERGED rather
/// than overwritten across feeds</b>.
///
/// <para>DIFFERENTIATORS #4 forbids an unexplained number. A Phase 7 risk score is built from a
/// CVSS vector one feed published, a KEV listing a second asserted, and an EPSS probability a third
/// computed — so "who said this, and when" has to survive every subsequent refresh of every OTHER
/// feed. Overwrite-on-upsert would erase the KEV and EPSS attribution on the next NVD sync and
/// leave a score no one could defend.</para>
///
/// <para>The merge is by <c>source</c>: a feed replaces its own entry and touches no other. That
/// makes attribution both complete and non-accumulating — the property the two tests at the centre
/// of this file assert from opposite directions.</para>
/// </summary>
[Collection(ContentPostgresCollection.Name)]
public sealed class ContentProvenanceTests(ContentPostgresFixture fx)
{
    private readonly ContentStore _store = new();

    [Fact]
    public async Task An_advisory_carries_the_provenance_of_every_feed_that_touched_it()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var id = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, cve), default));
        await Catalogue.CommittedAsync(conn, tx => _store.ApplyKevAsync(conn, tx, Kev(cve), default));
        await Catalogue.CommittedAsync(conn, tx => _store.ApplyEpssAsync(conn, tx, Epss(cve), default));

        Assert.Equal(
            new SortedSet<string> { Feeds.Nvd, Feeds.Kev, Feeds.Epss },
            new SortedSet<string>(await Catalogue.AdvisoryProvenanceSourcesAsync(conn, id)));
    }

    /// <summary>
    /// The merge's whole purpose. NVD re-syncs constantly; if its upsert overwrote provenance
    /// wholesale, every KEV and EPSS attribution in the catalogue would be erased on the next run
    /// while the <c>kev_*</c>/<c>epss_*</c> columns kept their values — leaving scores that are
    /// populated but unattributable, which is worse than either being absent.
    /// </summary>
    [Fact]
    public async Task A_publisher_resync_replaces_only_its_own_provenance_entry()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var id = await Catalogue.CommittedAsync(conn, tx => _store.UpsertAdvisoryAsync(
            conn, tx,
            Catalogue.Advisory(Feeds.Nvd, cve, retrievedAt: "2026-07-01T00:00:00Z"), default));
        await Catalogue.CommittedAsync(conn, tx => _store.ApplyKevAsync(conn, tx, Kev(cve), default));

        await Catalogue.CommittedAsync(conn, tx => _store.UpsertAdvisoryAsync(
            conn, tx,
            Catalogue.Advisory(Feeds.Nvd, cve, retrievedAt: "2026-07-29T00:00:00Z"), default));

        var sources = await Catalogue.AdvisoryProvenanceSourcesAsync(conn, id);

        // KEV's attribution survived an NVD refresh...
        Assert.Contains(Feeds.Kev, sources);

        // ...NVD's was REPLACED, not appended — one entry, carrying the newer timestamp. Appending
        // would grow the array without bound on a feed that refreshes hourly.
        Assert.Single(sources, s => s == Feeds.Nvd);
        Assert.StartsWith(
            "2026-07-29", await Catalogue.ProvenanceRetrievedAtAsync(conn, id, Feeds.Nvd));
    }

    /// <summary>The same property from the overlay's side: re-running KEV must not accumulate.</summary>
    [Fact]
    public async Task Re_applying_an_overlay_replaces_its_entry_rather_than_appending_another()
    {
        await using var conn = await fx.OpenAsync();
        var cve = $"CVE-2026-{Catalogue.Uid()}";

        var id = await Catalogue.CommittedAsync(conn, tx =>
            _store.UpsertAdvisoryAsync(conn, tx, Catalogue.Advisory(Feeds.Nvd, cve), default));

        await Catalogue.CommittedAsync(conn, tx =>
            _store.ApplyKevAsync(conn, tx, Kev(cve, "2026-07-01T00:00:00Z"), default));
        await Catalogue.CommittedAsync(conn, tx =>
            _store.ApplyKevAsync(conn, tx, Kev(cve, "2026-07-29T00:00:00Z"), default));

        var sources = await Catalogue.AdvisoryProvenanceSourcesAsync(conn, id);
        Assert.Single(sources, s => s == Feeds.Kev);
        Assert.StartsWith(
            "2026-07-29", await Catalogue.ProvenanceRetrievedAtAsync(conn, id, Feeds.Kev));
    }

    [Fact]
    public async Task A_patch_records_its_provenance_and_keeps_it_stable_across_a_resync()
    {
        await using var conn = await fx.OpenAsync();
        var kb = $"KB{Catalogue.Uid()}";

        var id = await Catalogue.CommittedAsync(conn, tx => _store.UpsertPatchAsync(
            conn, tx, Catalogue.Patch(Feeds.Msrc, kb, retrievedAt: "2026-07-01T00:00:00Z"), default));
        await Catalogue.CommittedAsync(conn, tx => _store.UpsertPatchAsync(
            conn, tx, Catalogue.Patch(Feeds.Msrc, kb, retrievedAt: "2026-07-29T00:00:00Z"), default));

        Assert.Equal([Feeds.Msrc], await Catalogue.PatchProvenanceSourcesAsync(conn, id));
    }

    /// <summary>
    /// The guard must sit on the STORE's path, not merely inside a helper. An advisory with no
    /// provenance is unattributable, and the DB CHECK would reject it anyway — but as a 23514 at
    /// the end of a batch, rolling back a whole feed's transaction for one bad record. Failing in
    /// the store names the offending record instead.
    /// </summary>
    [Fact]
    public async Task An_advisory_with_no_provenance_is_refused_before_it_reaches_the_database()
    {
        await using var conn = await fx.OpenAsync();
        var unattributable = Catalogue.Advisory(Feeds.Nvd, $"CVE-2026-{Catalogue.Uid()}") with
        {
            Provenance = [],
        };

        await Assert.ThrowsAsync<ArgumentException>(() => Catalogue.CommittedAsync(
            conn, tx => _store.UpsertAdvisoryAsync(conn, tx, unattributable, default)));
    }

    // -----------------------------------------------------------------------------------------

    private static KevOverlay Kev(string cve, string retrievedAt = "2026-07-29T00:00:00Z") =>
        new(cve,
            DateAdded: new DateOnly(2026, 7, 1),
            DueDate: new DateOnly(2026, 7, 22),
            KnownRansomwareUse: true,
            Provenance: Catalogue.Prov(Feeds.Kev, retrievedAt));

    private static EpssOverlay Epss(string cve, string retrievedAt = "2026-07-29T00:00:00Z") =>
        new(cve,
            Score: 0.94321,
            Percentile: 0.99876,
            ScoredAt: DateTimeOffset.Parse("2026-07-28T00:00:00Z"),
            Provenance: Catalogue.Prov(Feeds.Epss, retrievedAt));
}
