using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// <see cref="RhsaConnector.Parse"/> against a real captured page of the Red Hat securitydata list
/// (Samples/PROVENANCE.md).
///
/// <para>This connector was written against an envelope Red Hat does not serve — a root OBJECT with
/// an <c>advisories</c> array. The real endpoint returns a root ARRAY, and
/// <c>JsonHelpers.Array</c> returns <c>[]</c> for a non-object receiver, so the old parser produced
/// an empty batch that <c>ContentSyncService</c> recorded as <c>ok</c> with the cursor advanced. A
/// green sync over an empty catalogue — this project's "reports success while untrue" hazard.</para>
///
/// <para>Everything is asserted BY VALUE. The captured page is chosen so that a count cannot stand
/// in for a value: one advisory ships the same package at the same version across FOUR arches (the
/// rows must collapse to one, because <see cref="NormalizedAffect"/> has no arch and the DB key is
/// (advisory, package, ecosystem, platform)), and two advisories carry package strings that are not
/// NEVRA at all.</para>
/// </summary>
public sealed class RhsaParseTests
{
    private static readonly DateTimeOffset RetrievedAt =
        new(2026, 8, 21, 12, 0, 0, TimeSpan.Zero);

    private static NormalizedBatch Batch() => RhsaConnector.Parse(Samples.Rhsa(), RetrievedAt);

    private static NormalizedAdvisory Advisory(string externalId) =>
        Assert.Single(Batch().Advisories, a => a.ExternalId == externalId);

    // ---------------------------------------------------------------------------------------
    // The defect: the root is an array, not an object
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The whole point of the rewrite. Against the real payload the old parser produced zero
    /// advisories and no error; three is what the captured page actually contains.
    /// </summary>
    [Fact]
    public void The_array_root_is_read_rather_than_silently_yielding_nothing()
    {
        Assert.Equal(
            new SortedSet<string> { "RHSA-2026:57148", "RHSA-2026:57149", "RHSA-2026:57175" },
            new SortedSet<string>(Batch().Advisories.Select(a => a.ExternalId), StringComparer.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // NEVRA → fix statements
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>ansible-core-1:2.14.18-3.el9_8.1</c> ships on four arches in this advisory. Arch is not
    /// part of a fix statement, so the four collapse to ONE row per package — otherwise the store's
    /// upsert on (advisory, package, ecosystem, platform) would write one row and silently discard
    /// three, and the count would be a lie either way.
    /// </summary>
    [Fact]
    public void Packages_repeated_across_arches_collapse_to_one_fix_statement_each()
    {
        var advisory = Advisory("RHSA-2026:57149");

        Assert.Equal(
            new SortedSet<string> { "ansible-core", "ansible-test" },
            new SortedSet<string>(advisory.Affects.Select(a => a.PackageName), StringComparer.Ordinal));
    }

    /// <summary>
    /// The epoch is part of the version and is carried RAW (ADR 0011) — the Phase 6 rpm comparator
    /// owns <c>rpmvercmp</c> and epoch dominance. A non-zero epoch is the case that catches a parser
    /// splitting on the wrong separator: the package NAME here also contains digits and hyphens.
    /// </summary>
    [Fact]
    public void The_fixed_version_keeps_the_epoch_exactly_as_red_hat_wrote_it()
    {
        var affect = Assert.Single(Advisory("RHSA-2026:57149").Affects, a => a.PackageName == "ansible-core");

        Assert.Equal("1:2.14.18-3.el9_8.1", affect.FixedVersion);
        Assert.Equal(Ecosystems.Rpm, affect.Ecosystem);
        Assert.True(affect.Backported);
    }

    /// <summary>
    /// The platform comes from the dist tag, and the two advisories in this page target different
    /// RHEL majors — so a hardcoded platform passes on one and fails on the other.
    /// </summary>
    [Fact]
    public void The_rhel_major_is_derived_from_the_dist_tag()
    {
        Assert.Equal("rhel:9", Assert.Single(Advisory("RHSA-2026:57149").Affects, a => a.PackageName == "ansible-core").Platform);
        Assert.Equal("rhel:10", Assert.Single(Advisory("RHSA-2026:57148").Affects, a => a.PackageName == "ansible-core").Platform);
    }

    /// <summary>
    /// A source rpm is not installable, so it is not an applicability fact. Both advisories ship one
    /// (<c>ansible-core-1:…​.src</c>) and neither may produce a fix statement for it.
    /// </summary>
    [Fact]
    public void Source_rpms_are_not_fix_statements()
    {
        var affects = Batch().Advisories.SelectMany(a => a.Affects).ToList();

        Assert.NotEmpty(affects); // control: an empty set would satisfy the assertion below vacuously
        Assert.DoesNotContain(affects, a => a.FixedVersion!.EndsWith(".src", StringComparison.Ordinal));
    }

    /// <summary>
    /// <c>java-21-openjdk-portable-main@aarch64</c> is a module-stream reference, not a NEVRA — it
    /// carries no version at all, so it cannot state a fix. It must be skipped rather than turned
    /// into a row with a null or invented version.
    /// </summary>
    [Fact]
    public void A_package_reference_with_no_version_produces_no_fix_statement()
    {
        Assert.Empty(Advisory("RHSA-2026:57175").Affects);
    }

    // ---------------------------------------------------------------------------------------
    // Advisory and patch fields
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Red Hat's four-band severity maps onto our five-band vocabulary; <c>important</c> is the one
    /// that would silently pass through as an illegal value if the map were dropped.
    /// </summary>
    [Fact]
    public void The_advisory_carries_red_hats_identity_severity_and_release_time()
    {
        var advisory = Advisory("RHSA-2026:57148");

        Assert.Equal(Feeds.Rhsa, advisory.Source);
        Assert.Equal("high", advisory.Severity); // Red Hat says "important"
        Assert.Equal(new DateTimeOffset(2026, 8, 19, 20, 18, 34, TimeSpan.Zero), advisory.PublishedAt);
    }

    /// <summary>
    /// The summary payload carries no title field. Falling back to the id is honest; inventing a
    /// title would not be, and <c>Title</c> is a required member so it cannot simply be omitted.
    /// </summary>
    [Fact]
    public void The_title_falls_back_to_the_advisory_id_because_the_feed_has_no_title()
    {
        Assert.Equal("RHSA-2026:57148", Advisory("RHSA-2026:57148").Title);
    }

    [Fact]
    public void The_cves_the_advisory_fixes_are_preserved_in_source_metadata()
    {
        using var metadata = System.Text.Json.JsonDocument.Parse(Advisory("RHSA-2026:57148").SourceMetadataJson!);

        Assert.Equal(
            new[] { "CVE-2026-11332" },
            metadata.RootElement.GetProperty("cves").EnumerateArray().Select(e => e.GetString()).ToArray());
    }

    [Fact]
    public void Provenance_names_the_feed_the_advisory_and_the_errata_page()
    {
        var entry = Assert.Single(Advisory("RHSA-2026:57148").Provenance);

        Assert.Equal(Feeds.Rhsa, entry.Source);
        Assert.Equal(RetrievedAt, entry.RetrievedAt);
        Assert.Equal("RHSA-2026:57148", entry.SourceRecordId);
        Assert.Equal("https://access.redhat.com/errata/RHSA-2026:57148", entry.Url);
    }

    /// <summary>
    /// An RHSA is an installable action, so it is a patch too. The summary carries no reboot flag —
    /// <c>false</c> here means "not stated", which is recorded in the connector rather than presented
    /// as a vendor assertion.
    /// </summary>
    [Fact]
    public void Each_advisory_also_produces_a_patch_keyed_on_the_same_id()
    {
        var patch = Assert.Single(Batch().Patches, p => p.VendorId == "RHSA-2026:57148");

        Assert.Equal(Feeds.Rhsa, patch.Source);
        Assert.False(patch.Reversible);
        Assert.Empty(patch.Supersedes);
    }

    /// <summary>The cursor is the newest release timestamp on the page, round-trippable.</summary>
    [Fact]
    public void The_cursor_is_the_newest_release_time_in_the_response()
    {
        Assert.Equal(
            new DateTimeOffset(2026, 8, 19, 20, 50, 44, TimeSpan.Zero),
            DateTimeOffset.Parse(Batch().Cursor!, null, System.Globalization.DateTimeStyles.RoundtripKind));
    }

    // ---------------------------------------------------------------------------------------
    // Fail loudly — ADR 0022's mitigation (a), applied retroactively to the feed that needed it
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The defect in one assertion: the OLD parser returned an empty batch for an object root and
    /// the sync called that <c>ok</c>. A shape it does not understand must now throw, so
    /// <c>ContentSyncService</c> records <c>failed</c> and holds the cursor.
    /// </summary>
    [Fact]
    public void An_unexpected_root_shape_throws_instead_of_yielding_an_empty_batch()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => RhsaConnector.Parse("""{"advisories":[]}""", RetrievedAt));

        Assert.Contains("array", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The subtler half: the root is the right shape, but nothing usable came out of it. A feed of
    /// thousands that yields zero advisories is a format change, not an empty Tuesday.
    /// </summary>
    [Fact]
    public void A_non_empty_document_that_yields_no_advisories_throws()
    {
        Assert.Throws<InvalidOperationException>(
            () => RhsaConnector.Parse("""[{"not_an_advisory":true}]""", RetrievedAt));
    }

    /// <summary>An genuinely empty page is not a defect — it is a page with nothing on it.</summary>
    [Fact]
    public void A_genuinely_empty_page_is_accepted_as_empty()
    {
        var batch = RhsaConnector.Parse("[]", RetrievedAt);

        Assert.Empty(batch.Advisories);
        Assert.Empty(batch.Patches);
    }

    /// <summary>RHSA publishes fixes, never exploitation or scoring overlays.</summary>
    [Fact]
    public void Rhsa_emits_no_overlays()
    {
        var batch = Batch();

        Assert.Empty(batch.KevOverlays);
        Assert.Empty(batch.EpssOverlays);
    }
}
