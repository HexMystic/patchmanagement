using PatchManagement.Content.Abstractions;
using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// <see cref="Wsusscn2Connector.ParseAsync"/> against a captured slice of the real cab
/// (Samples/PROVENANCE.md — 20 revisions of real bytes, graph plus all three blob families).
///
/// <para>This is the feed ADR 0008 designates the Windows <b>applicability engine</b>, and until
/// this slice it ingested <b>nothing while reporting <c>ok</c></b>. The old parser looked for
/// <c>KBArticleID</c>, <c>Title</c>, <c>RebootBehavior</c> and <c>IsSoftware="true"</c> in
/// <c>package.xml</c>, where none of them occur — the graph carries only identity and relationships,
/// and every one of those fields lives in a sibling shard keyed by <c>RevisionId</c>.</para>
///
/// <para>The fixtures are chosen so a count cannot stand in for a value: a Detectoid and a Category
/// that must be dropped, revisions with a KB and revisions without one (which fall back to
/// <c>UpdateId</c>), a supersedence pair whose BOTH ends are present, and a supersedence edge whose
/// other end is deliberately absent.</para>
/// </summary>
public sealed class Wsusscn2ParseTests
{
    private static readonly DateTimeOffset RetrievedAt =
        new(2026, 8, 21, 12, 0, 0, TimeSpan.Zero);

    private static async Task<NormalizedBatch> BatchAsync()
    {
        await using var source = new FakeWsusCatalogSource();
        return await Wsusscn2Connector.ParseAsync(source, RetrievedAt, CancellationToken.None);
    }

    private static async Task<NormalizedPatch> PatchAsync(string vendorId) =>
        Assert.Single((await BatchAsync()).Patches, p => p.VendorId == vendorId);

    // ---------------------------------------------------------------------------------------
    // The discriminator — the reason every update was skipped
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The real software-vs-category flag is <c>c/&lt;n&gt;</c>'s <c>Properties/@UpdateType</c>, not
    /// <c>package.xml</c>'s <c>IsSoftware</c> (which is <c>"false"</c> on every update in the real
    /// catalogue). The slice holds 18 Software revisions plus one Detectoid and one Category — and
    /// yields <b>17</b> patches, not 18, because two of those revisions share a KB (see below).
    /// </summary>
    [Fact]
    public async Task Only_software_updates_become_patches()
    {
        Assert.Equal(17, (await BatchAsync()).Patches.Count);
    }

    /// <summary>
    /// <b>One KB, two updates.</b> KB5101650 arrives as revisions 33 and 616 with DIFFERENT
    /// <c>UpdateId</c>s — Microsoft ships one KB article across product families, each its own
    /// update. <c>patches</c> is unique on <c>(source, vendor_id)</c> and the vendor id IS the KB, so
    /// they must collapse to one row: emitting both would have the store keep whichever landed last
    /// and the reported count describe nothing real. The same collapse MSRC needed, for the same
    /// reason, arrived at from the opposite direction.
    /// </summary>
    [Fact]
    public async Task Several_revisions_of_one_kb_collapse_to_a_single_patch()
    {
        var batch = await BatchAsync();

        Assert.Single(batch.Patches, p => p.VendorId == "KB5101650");
        // And the collapse does not lose the edge that only one of the two carried.
        Assert.Equal(["KB5094126"], Assert.Single(batch.Patches, p => p.VendorId == "KB5101650").Supersedes);
    }

    /// <summary>
    /// Revision 3 is a Detectoid and revision 5 a Category — applicability machinery and taxonomy,
    /// not installable updates. A real catalogue carries thousands of each; admitting them would
    /// fill the patch table with rows no host can ever install.
    /// </summary>
    [Fact]
    public async Task Detectoids_and_categories_are_not_patches()
    {
        var ids = (await BatchAsync()).Patches
            .Select(p => p.SourceMetadataJson!)
            .ToList();

        Assert.DoesNotContain(ids, m => m.Contains("\"revisionId\":3,", StringComparison.Ordinal));
        Assert.DoesNotContain(ids, m => m.Contains("\"revisionId\":5,", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // Fields, each from the shard family that actually holds it
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// KB from <c>x/&lt;n&gt;</c>, title from <c>l/en/&lt;n&gt;</c>, severity from
    /// <c>x/&lt;n&gt;</c>'s <c>MsrcSeverity</c>. Three fields, three different files, one revision —
    /// which is the whole reason the seam had to become shard-aware.
    /// </summary>
    [Fact]
    public async Task A_patch_takes_its_kb_from_x_and_its_title_from_l()
    {
        var patch = await PatchAsync("KB5087058");

        Assert.Equal(Feeds.Wsusscn2, patch.Source);
        Assert.Equal(
            "2026-05 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 23H2 for x64 (KB5087058)",
            patch.Title);
        Assert.Contains("\"msrcSeverity\":\"Critical\"", patch.SourceMetadataJson!, StringComparison.Ordinal);
    }

    /// <summary>
    /// Not every revision has a KB — 370 of the 626 in this shard do not. Those are real updates and
    /// must still be ingested, keyed on <c>UpdateId</c>. Dropping them would silently shrink the
    /// Windows catalogue, and the title falls back too because they have no <c>l/en</c> entry either.
    /// </summary>
    [Fact]
    public async Task A_revision_with_no_kb_falls_back_to_its_update_id()
    {
        var patch = await PatchAsync("8d06a0ee-d9e0-478b-b168-5f0a514b78a6");

        Assert.Equal("8d06a0ee-d9e0-478b-b168-5f0a514b78a6", patch.Title);
    }

    /// <summary>
    /// <c>RebootBehavior</c> lives in <c>x/&lt;n&gt;</c>'s <c>InstallationBehavior</c> — phase-5.md
    /// recorded it as "must be located" after a four-file sample missed it. Found, and read:
    /// <c>CanRequestReboot</c> means a maintenance window must assume a reboot.
    /// </summary>
    [Fact]
    public async Task Requires_reboot_is_read_from_the_extended_properties()
    {
        Assert.True((await PatchAsync("8d06a0ee-d9e0-478b-b168-5f0a514b78a6")).RequiresReboot);
    }

    /// <summary>
    /// <c>Uninstallable</c> does NOT exist anywhere in the catalogue's blobs — zero occurrences
    /// across all 626 <c>c/</c> and <c>x/</c> files in the shard. So <c>reversible</c> stays false
    /// as an honest "the vendor did not say", which gates rollback OFF (DIFFERENTIATORS #1). That is
    /// the safe direction, and it is a stated limit rather than a silent default.
    /// </summary>
    [Fact]
    public async Task Reversible_is_false_because_the_catalogue_never_states_it()
    {
        Assert.All((await BatchAsync()).Patches, p => Assert.False(p.Reversible));
    }

    // ---------------------------------------------------------------------------------------
    // Supersedence — the Windows half of the HARD-PROBLEMS #4 DAG
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The inversion, which is the one part of the old parser that was right against real data.
    /// Revision 21 (KB5094126, the June cumulative) says it is superseded by revision 616
    /// (KB5101650, July). The edge must land on the NEWER patch as "supersedes the older one", or
    /// Phase 6 cannot resolve a missing patch to its effective head.
    /// </summary>
    [Fact]
    public async Task A_superseded_by_revision_becomes_a_supersedes_edge_on_the_newer_patch()
    {
        Assert.Equal(["KB5094126"], (await PatchAsync("KB5101650")).Supersedes);
        Assert.Empty((await PatchAsync("KB5094126")).Supersedes);
    }

    /// <summary>
    /// Revision 1 is superseded by revision 222, which is deliberately NOT in the captured slice.
    /// An edge needs both endpoints to exist as patches — inventing one would fabricate a
    /// relationship the catalogue does not support, and the store's upsert would reject the dangling
    /// vendor id anyway.
    /// </summary>
    [Fact]
    public async Task A_supersedence_edge_whose_other_end_is_absent_produces_nothing()
    {
        Assert.DoesNotContain(
            (await BatchAsync()).Patches,
            p => p.Supersedes.Contains("KB5087058", StringComparer.OrdinalIgnoreCase));
    }

    // ---------------------------------------------------------------------------------------
    // Identity, provenance, cursor, negative space
    // ---------------------------------------------------------------------------------------

    /// <summary>The graph drives the lookups: every update in package.xml is resolved by RevisionId.</summary>
    [Fact]
    public async Task Every_update_in_the_graph_is_looked_up_by_its_revision_id()
    {
        await using var source = new FakeWsusCatalogSource();
        await Wsusscn2Connector.ParseAsync(source, RetrievedAt, CancellationToken.None);

        Assert.Equal(20, source.Requested.Count);
        Assert.Contains(616L, source.Requested);
    }

    [Fact]
    public async Task Provenance_names_the_feed_and_the_update_it_came_from()
    {
        var entry = Assert.Single((await PatchAsync("KB5101650")).Provenance);

        Assert.Equal(Feeds.Wsusscn2, entry.Source);
        Assert.Equal(RetrievedAt, entry.RetrievedAt);
        Assert.Equal("64c52254-175b-4e2c-8a7c-30e3c24ae1d1", entry.SourceRecordId);
    }

    /// <summary>The catalogue's own PackageId — a real root attribute and a sound bookmark.</summary>
    [Fact]
    public async Task The_cursor_is_the_catalogues_package_id()
    {
        Assert.Equal("e1a000e0-066b-497a-ba62-246d4af43e55", (await BatchAsync()).Cursor);
    }

    /// <summary>
    /// wsusscn2 is the applicability half of ADR 0008: it publishes patches and supersedence, never
    /// advisories. MSRC is the CVE side, and a wsusscn2 advisory row is rejected by CHECK anyway.
    /// </summary>
    [Fact]
    public async Task Wsusscn2_emits_patches_only()
    {
        var batch = await BatchAsync();

        Assert.Empty(batch.Advisories);
        Assert.Empty(batch.KevOverlays);
        Assert.Empty(batch.EpssOverlays);
    }

    // ---------------------------------------------------------------------------------------
    // Fail loudly — ADR 0022's mitigation (a)
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The defect in one assertion. A graph that parses but yields no patches is a format change —
    /// which is exactly what happened here, silently, and was recorded as `ok` with the cursor
    /// advanced. It must throw instead.
    /// </summary>
    [Fact]
    public async Task A_graph_that_yields_no_patches_throws()
    {
        await using var source = new EmptyGraphSource();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Wsusscn2Connector.ParseAsync(source, RetrievedAt, CancellationToken.None));

        Assert.Contains("wsusscn2", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A catalogue with no updates at all is empty, which is a different fact from broken.</summary>
    [Fact]
    public async Task A_catalogue_with_no_updates_is_accepted_as_empty()
    {
        await using var source = new EmptyGraphSource(withUpdates: false);

        var batch = await Wsusscn2Connector.ParseAsync(source, RetrievedAt, CancellationToken.None);

        Assert.Empty(batch.Patches);
    }

    /// <summary>A graph whose updates all resolve to nothing — the shape the old parser produced.</summary>
    private sealed class EmptyGraphSource(bool withUpdates = true) : IWsusCatalogSource
    {
        public Task<Stream> OpenPackageXmlAsync(CancellationToken ct)
        {
            var body = withUpdates
                ? """<Update UpdateId="u" RevisionId="99" />"""
                : "";
            return Task.FromResult<Stream>(new MemoryStream(
                System.Text.Encoding.UTF8.GetBytes(
                    $"""<OfflineSyncPackage PackageId="p"><Updates>{body}</Updates></OfflineSyncPackage>""")));
        }

        public Task<WsusRevision?> OpenRevisionAsync(long revisionId, CancellationToken ct) =>
            Task.FromResult<WsusRevision?>(null);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
