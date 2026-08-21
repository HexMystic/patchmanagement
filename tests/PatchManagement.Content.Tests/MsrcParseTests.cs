using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// <see cref="MsrcConnector.Parse"/> against a real captured CVRF document (Samples/PROVENANCE.md,
/// four complete vulnerabilities from <c>2026-Aug</c>).
///
/// <para>The old connector pointed at <c>cvrf/v3.0/csaf</c>, which returns <b>400</b>, and parsed an
/// invented <c>root.vulnerabilities[].remediations[].kb</c> envelope. Microsoft serves CVRF: a
/// monthly index at <c>cvrf/v3.0/updates</c>, then a document per month with
/// <c>Vulnerability[]</c>, <c>Remediations[]</c> and a <c>ProductTree</c> that <c>ProductID</c>s
/// resolve against.</para>
///
/// <para><b>The remediation types are not what the CVRF spec's numbering implies</b>, which is why
/// this had to be captured rather than assumed. <b>Type 2</b> is the vendor fix and carries the KB
/// in <c>Description.Value</c>, plus <c>FixedBuild</c>, <c>RestartRequired</c> and
/// <c>Supercedence</c>. <b>Type 3</b> carries no <c>Description</c> at all. And Type 2's description
/// is only <em>sometimes</em> a KB — for non-Windows products it is a label such as
/// <c>"Release Notes"</c>, which must never become a patch id.</para>
/// </summary>
public sealed class MsrcParseTests
{
    private static readonly DateTimeOffset RetrievedAt =
        new(2026, 8, 21, 12, 0, 0, TimeSpan.Zero);

    private static NormalizedBatch Batch() => MsrcConnector.Parse(Samples.Msrc(), RetrievedAt);

    private static NormalizedAdvisory Advisory(string cve) =>
        Assert.Single(Batch().Advisories, a => a.ExternalId == cve);

    // ---------------------------------------------------------------------------------------
    // The document is read at all
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Every_vulnerability_in_the_document_becomes_an_advisory()
    {
        Assert.Equal(
            new SortedSet<string>
            {
                "CVE-2026-50472", "CVE-2026-58650", "CVE-2026-62896", "CVE-2026-65768",
            },
            new SortedSet<string>(Batch().Advisories.Select(a => a.ExternalId), StringComparer.Ordinal));
    }

    /// <summary>The cursor is the document's own month id — the unit Microsoft publishes in.</summary>
    [Fact]
    public void The_cursor_is_the_documents_month_id()
    {
        Assert.Equal("2026-Aug", Batch().Cursor);
    }

    // ---------------------------------------------------------------------------------------
    // Type 2 is the vendor fix — KB, build, reboot, supersedence
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The KB lives in a Type 2 remediation's <c>Description.Value</c>. One CVE routinely ships
    /// several KBs — one per product family — and they are asserted by value because a count would
    /// pass with the wrong three.
    /// </summary>
    [Fact]
    public void The_kbs_come_from_type_2_remediations_and_are_prefixed()
    {
        var kbs = Batch().Patches.Select(p => p.VendorId).ToHashSet(StringComparer.Ordinal);

        Assert.Contains("KB5120238", kbs);
        Assert.Contains("KB5120242", kbs);
        Assert.Contains("KB5120229", kbs);
    }

    /// <summary>
    /// <c>Supercedence</c> is what feeds the Windows half of the supersedence DAG (HARD-PROBLEMS #4).
    /// It sits on Type 2 alongside the KB, and only some remediations carry one.
    /// </summary>
    [Fact]
    public void Supersedence_is_read_from_the_same_type_2_remediation_as_the_kb()
    {
        var patch = Assert.Single(Batch().Patches, p => p.VendorId == "KB5120238");

        Assert.Equal(["KB5082123"], patch.Supersedes);
    }

    /// <summary>A KB with no <c>Supercedence</c> supersedes nothing — not "unknown", nothing.</summary>
    [Fact]
    public void A_remediation_without_supercedence_supersedes_nothing()
    {
        Assert.Empty(Assert.Single(Batch().Patches, p => p.VendorId == "KB5120229").Supersedes);
    }

    /// <summary>
    /// <c>requires_reboot</c> finally comes from real vendor data rather than a hardcoded false.
    /// Microsoft states <c>Yes</c>, <c>No</c> or <c>Maybe</c>; <c>Maybe</c> is treated as true,
    /// because planning a maintenance window that turns out to need a reboot is the harmful
    /// direction and HARD-PROBLEMS #8 forbids collapsing an unknown into the benign answer.
    /// </summary>
    [Fact]
    public void Requires_reboot_is_taken_from_the_vendors_restart_flag()
    {
        Assert.True(Assert.Single(Batch().Patches, p => p.VendorId == "KB5120238").RequiresReboot);
    }

    /// <summary>
    /// The trap that makes this feed dangerous to guess at: for non-Windows products Type 2's
    /// description is a LABEL, not a KB. Visual Studio Code and Teams both carry
    /// <c>"Release Notes"</c>, and a parser that trusted the field would mint a patch whose
    /// <c>vendor_id</c> is the string "Release Notes" — and then dedupe every such product onto it.
    /// </summary>
    [Fact]
    public void A_type_2_description_that_is_not_a_kb_never_becomes_a_patch()
    {
        var ids = Batch().Patches.Select(p => p.VendorId).ToList();

        Assert.NotEmpty(ids); // control: no patches at all would satisfy the assertions below vacuously
        Assert.DoesNotContain(ids, id => id.Contains("Release Notes", StringComparison.OrdinalIgnoreCase));
        Assert.All(ids, id => Assert.StartsWith("KB", id, StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // Fix statements — products resolved through the ProductTree
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A remediation names products by opaque <c>ProductID</c>; the human name lives in
    /// <c>ProductTree.FullProductName</c>. Without that resolution a fix statement's package would
    /// be a number like "11568", which no inventory could ever match.
    /// </summary>
    [Fact]
    public void The_product_id_is_resolved_to_its_name_through_the_product_tree()
    {
        var affect = Assert.Single(
            Advisory("CVE-2026-50472").Affects,
            a => a.PackageName == "Windows 10 Version 1809 for 32-bit Systems");

        Assert.Equal("10.0.17763.9121", affect.FixedVersion);
        Assert.Equal(Ecosystems.Windows, affect.Ecosystem);
    }

    /// <summary>
    /// A non-Windows product still states a real fixed version even though it has no KB — the
    /// advisory side and the patch side are independent, and dropping the affect because the
    /// remediation had no KB would lose the applicability fact entirely.
    /// </summary>
    [Fact]
    public void A_product_with_no_kb_still_produces_a_fix_statement()
    {
        var affect = Assert.Single(Advisory("CVE-2026-58650").Affects);

        Assert.Equal("Visual Studio Code", affect.PackageName);
        Assert.Equal("1.132.1", affect.FixedVersion);
    }

    /// <summary>
    /// One CVE can ship TWO KBs for the same product — here a cumulative and a security-only update
    /// for Windows Server 2022, at builds …5499 and …5440. <c>advisory_affects</c> is unique on
    /// (advisory, package, ecosystem, platform), so both cannot be stored: emitting the pair would
    /// have the store keep whichever landed last, and the reported count would describe nothing.
    /// The LOWEST build is kept, because a host that installed either KB is fixed and the lower
    /// build is the threshold at which that becomes true — taking the higher would report patched
    /// hosts as vulnerable.
    /// </summary>
    [Fact]
    public void Two_kbs_fixing_one_product_collapse_to_the_lowest_fixed_build()
    {
        var affect = Assert.Single(
            Advisory("CVE-2026-50472").Affects, a => a.PackageName == "Windows Server 2022");

        Assert.Equal("10.0.20348.5440", affect.FixedVersion);
    }

    /// <summary>
    /// Windows fix statements are build thresholds, not package versions, and are carried RAW
    /// (ADR 0011) — the Phase 6 comparator owns the four-part numeric compare.
    /// </summary>
    [Fact]
    public void Windows_fix_statements_are_never_marked_backported()
    {
        var affects = Advisory("CVE-2026-50472").Affects;

        Assert.NotEmpty(affects);
        Assert.All(affects, a => Assert.False(a.Backported));
    }

    // ---------------------------------------------------------------------------------------
    // Advisory fields, and the sentinel that must not become a date
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>ReleaseDate</c> is <c>0001-01-01T00:00:00</c> with <c>ReleaseDateSpecified: false</c> —
    /// a sentinel, not a date. Parsing it produces a real <c>DateTimeOffset</c> in year 1, which
    /// would sort ahead of everything and read as a genuine publication date. Unstated must stay
    /// null (HARD-PROBLEMS #8).
    /// </summary>
    [Fact]
    public void An_unspecified_release_date_is_null_rather_than_the_year_one_sentinel()
    {
        Assert.Null(Advisory("CVE-2026-50472").PublishedAt);
    }

    /// <summary>
    /// Severity is a Threat of type 3, not a field on the vulnerability. Both bands present in the
    /// captured document are asserted, so a map that returns a constant fails.
    /// </summary>
    [Fact]
    public void Severity_comes_from_the_threat_entry_and_maps_onto_our_bands()
    {
        Assert.Equal("high", Advisory("CVE-2026-50472").Severity);      // Microsoft says "Important"
        Assert.Equal("critical", Advisory("CVE-2026-62896").Severity);  // Microsoft says "Critical"
    }

    [Fact]
    public void The_cvss_score_and_vector_are_attributed_to_msrc()
    {
        var advisory = Advisory("CVE-2026-62896");

        Assert.Equal(9.6, advisory.CvssBaseScore);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N/E:U/RL:O/RC:C", advisory.CvssVector);
        Assert.Equal(Feeds.Msrc, advisory.CvssSource);
    }

    [Fact]
    public void Provenance_names_the_feed_the_cve_and_the_update_guide_page()
    {
        var entry = Assert.Single(Advisory("CVE-2026-50472").Provenance);

        Assert.Equal(Feeds.Msrc, entry.Source);
        Assert.Equal(RetrievedAt, entry.RetrievedAt);
        Assert.Equal("CVE-2026-50472", entry.SourceRecordId);
        Assert.Equal(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50472", entry.Url);
    }

    /// <summary>
    /// A vulnerability with no remediations is normal — 333 of the 800 in this document have none.
    /// It is an advisory with nothing to install yet, not a parse failure.
    /// </summary>
    [Fact]
    public void A_vulnerability_with_no_remediations_is_an_advisory_with_no_fix_statements()
    {
        var advisory = Advisory("CVE-2026-62896");

        Assert.Empty(advisory.Affects);
        Assert.Equal("critical", advisory.Severity);
    }

    // ---------------------------------------------------------------------------------------
    // Fail loudly — ADR 0022's mitigation (a)
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The old envelope in one assertion. A document without <c>Vulnerability</c> is a format
    /// change, and must fail the sync rather than produce an empty batch reported as <c>ok</c>.
    /// </summary>
    [Fact]
    public void A_document_without_a_vulnerability_array_throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => MsrcConnector.Parse("""{"vulnerabilities":[]}""", RetrievedAt));

        Assert.Contains("Vulnerability", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The subtler half: the array is there but nothing usable came out of it — a renamed
    /// <c>CVE</c> field would look exactly like this.
    /// </summary>
    [Fact]
    public void A_document_whose_entries_yield_no_advisories_throws()
    {
        Assert.Throws<InvalidOperationException>(
            () => MsrcConnector.Parse("""{"Vulnerability":[{"Ordinal":"1"}]}""", RetrievedAt));
    }

    /// <summary>MSRC publishes advisories and KBs, never exploitation or scoring overlays.</summary>
    [Fact]
    public void Msrc_emits_no_overlays()
    {
        var batch = Batch();

        Assert.Empty(batch.KevOverlays);
        Assert.Empty(batch.EpssOverlays);
    }

    // ---------------------------------------------------------------------------------------
    // The monthly index — the first of the two calls a sync makes
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The newest month is chosen by <c>InitialReleaseDate</c>, not <c>CurrentReleaseDate</c>:
    /// several months share the same <c>CurrentReleaseDate</c> (they are revised together), so a max
    /// over that field depends on array order rather than on which month is actually newest.
    /// </summary>
    [Fact]
    public void The_newest_month_is_selected_by_initial_release_date()
    {
        Assert.Equal("2026-Aug", MsrcConnector.NewestMonth(Samples.MsrcUpdates()).Id);
    }

    [Fact]
    public void The_selected_month_carries_the_url_the_second_call_uses()
    {
        Assert.Equal(
            "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Aug",
            MsrcConnector.NewestMonth(Samples.MsrcUpdates()).CvrfUrl);
    }

    /// <summary>An index with no entries cannot yield a month, and must say so.</summary>
    [Fact]
    public void An_index_with_no_months_throws()
    {
        Assert.Throws<InvalidOperationException>(
            () => MsrcConnector.NewestMonth("""{"value":[]}"""));
    }
}
