using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// <see cref="KevConnector.Parse"/> against a real CISA KEV capture (Samples/PROVENANCE.md — real
/// envelope, two records retained byte-for-byte, array truncated).
///
/// <para>KEV is an OVERLAY. It asserts that a CVE is known-exploited; it publishes no advisory, and
/// the schema forbids <c>source = 'kev'</c> outright. The asymmetry is asserted here, not assumed.</para>
/// </summary>
public sealed class KevParseTests
{
    private static readonly DateTimeOffset RetrievedAt =
        new(2026, 7, 28, 12, 0, 0, TimeSpan.Zero);

    private static KevOverlay Overlay(string cve) =>
        Assert.Single(
            KevConnector.Parse(Samples.Kev(), RetrievedAt).KevOverlays,
            o => o.CveId == cve);

    [Fact]
    public void An_entry_carries_its_cve_the_date_added_and_the_bod_2201_deadline()
    {
        var overlay = Overlay("CVE-2021-40539");

        Assert.Equal(new DateOnly(2021, 11, 3), overlay.DateAdded);
        Assert.Equal(new DateOnly(2021, 11, 17), overlay.DueDate);
    }

    /// <summary>
    /// CISA saying "Known" is a positive assertion, and it must survive as one.
    /// </summary>
    [Fact]
    public void Confirmed_ransomware_use_is_recorded_as_true()
    {
        Assert.True(Overlay("CVE-2021-40539").KnownRansomwareUse);
    }

    /// <summary>
    /// CISA's literal string here is "Unknown", which means <em>not confirmed</em> — not
    /// <em>confirmed absent</em>. Recording it as <c>false</c> would let Phase 7 read an absence of
    /// evidence as evidence of absence and weight the CVE as if ransomware use had been ruled out.
    ///
    /// <para>The frozen schema already settles this shape for the sibling field: <c>kev.listed</c>'s
    /// own description says collapsing "not evaluated" into false "would let Phase 7 weight a
    /// never-run sync identically to a confirmed absence". <c>knownRansomwareUse</c> is
    /// <c>[boolean, null]</c> and <c>advisories.kev_known_ransomware_use</c> is nullable, so the
    /// third state is representable — and the connector's own comment already said it should be
    /// null. The code disagreed with that comment until this test.</para>
    /// </summary>
    [Fact]
    public void Unconfirmed_ransomware_use_is_null_not_false()
    {
        Assert.Null(Overlay("CVE-2020-29583").KnownRansomwareUse);
    }

    /// <summary>
    /// Provenance points at the human-readable catalogue page, deliberately NOT at
    /// <see cref="KevConnector.DefaultEndpoint"/> (the raw JSON feed) — an auditor following the
    /// trail wants the catalogue, not a download.
    /// </summary>
    [Fact]
    public void Provenance_cites_the_catalogue_page_rather_than_the_json_endpoint()
    {
        var entry = Overlay("CVE-2021-40539").Provenance;

        Assert.Equal(Feeds.Kev, entry.Source);
        Assert.Equal(RetrievedAt, entry.RetrievedAt);
        Assert.Equal("CVE-2021-40539", entry.SourceRecordId);
        Assert.Equal("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", entry.Url);
        Assert.NotEqual(KevConnector.DefaultEndpoint, entry.Url);
    }

    [Fact]
    public void The_cursor_is_the_catalogue_version()
    {
        Assert.Equal("2026.07.27", KevConnector.Parse(Samples.Kev(), RetrievedAt).Cursor);
    }

    /// <summary>
    /// The asymmetry: KEV enriches, it never publishes. A row with <c>source = 'kev'</c> is rejected
    /// by the DB CHECK and would let one CVE exist as divergent duplicate rows.
    /// </summary>
    [Fact]
    public void Kev_emits_overlays_only_never_an_advisory_or_a_patch()
    {
        var batch = KevConnector.Parse(Samples.Kev(), RetrievedAt);

        Assert.Empty(batch.Advisories);
        Assert.Empty(batch.Patches);
        Assert.Empty(batch.EpssOverlays);

        // By CVE, not by count — a count would pass if the parser emitted the same record twice.
        Assert.Equal(
            new SortedSet<string> { "CVE-2021-40539", "CVE-2020-29583" },
            new SortedSet<string>(batch.KevOverlays.Select(o => o.CveId), StringComparer.Ordinal));
    }

    /// <summary>
    /// The fixture's <c>count</c> is the real catalogue's 1,655 while the array holds 2 — a
    /// deliberate mismatch (see PROVENANCE.md). The parser must derive nothing from <c>count</c>;
    /// if it ever did, it would over-report against the live feed too, where the two agree and the
    /// bug would be invisible.
    /// </summary>
    [Fact]
    public void The_declared_count_is_ignored_in_favour_of_the_records_actually_present()
    {
        Assert.Contains("\"count\": 1655", Samples.Kev(), StringComparison.Ordinal);

        Assert.Equal(2, KevConnector.Parse(Samples.Kev(), RetrievedAt).KevOverlays.Count);
    }
}
