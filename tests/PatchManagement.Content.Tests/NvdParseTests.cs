using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// <see cref="NvdConnector.Parse"/> against real captured NVD 2.0 responses (Samples/PROVENANCE.md).
///
/// <para>Everything is asserted BY VALUE. A count assertion passes for the wrong reason — the whole
/// point of the CVSS cases below is that a parser can emit the right <em>number</em> of advisories
/// carrying somebody else's score.</para>
/// </summary>
public sealed class NvdParseTests
{
    private static readonly DateTimeOffset RetrievedAt =
        new(2026, 7, 28, 12, 0, 0, TimeSpan.Zero);

    private static NormalizedAdvisory ParseOne(string cve)
    {
        var batch = NvdConnector.Parse(Samples.Nvd(cve), RetrievedAt);
        return Assert.Single(batch.Advisories);
    }

    // ---------------------------------------------------------------------------------------
    // The CVSS selection cases — the reason these particular CVEs were captured
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// NVD lists a CNA's Secondary metric BEFORE its own Primary for this CVE, and the two disagree
    /// across a severity band: vuldb says 7.3/HIGH, NVD says 9.8/CRITICAL.
    ///
    /// <para>Taking the first entry in the array therefore imports a third party's opinion and then
    /// labels it as NVD's. A scan of 300 consecutive real CVEs found 125 shaped this way, so this is
    /// roughly 40% of the feed, not a curiosity.</para>
    /// </summary>
    [Fact]
    public void The_nvd_primary_score_wins_over_a_cna_secondary_listed_before_it()
    {
        var advisory = ParseOne("CVE-2024-0182");

        Assert.Equal(9.8, advisory.CvssBaseScore);
        Assert.Equal("critical", advisory.Severity);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", advisory.CvssVector);
        Assert.Equal("3.1", advisory.CvssVersion);

        // And having actually taken NVD's metric, saying so is now true.
        Assert.Equal(Feeds.Nvd, advisory.CvssSource);
    }

    /// <summary>
    /// Qualcomm scored this one; NVD published no Primary at all. The score is real and worth
    /// keeping — but NVD did not supply it, and <c>CvssSource</c> exists precisely to record which
    /// feed did ("NVD and a vendor routinely disagree").
    ///
    /// <para><c>cvss.source</c> is <c>$ref: #/$defs/feed</c> in <c>schemas/advisory.schema.json</c>
    /// and <c>advisories.cvss_source</c> is CHECK-constrained to the same eight feed names, so
    /// "product-security@qualcomm.com" cannot be recorded there. NULL is permitted by both, and is
    /// the honest answer: we have a score, and it is not NVD's.</para>
    /// </summary>
    [Fact]
    public void A_score_nvd_did_not_publish_is_kept_but_not_attributed_to_nvd()
    {
        var advisory = ParseOne("CVE-2023-33025");

        Assert.Equal(9.8, advisory.CvssBaseScore);
        Assert.Equal("critical", advisory.Severity);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", advisory.CvssVector);

        Assert.Null(advisory.CvssSource);
    }

    /// <summary>
    /// Nulling <c>CvssSource</c> stops the lie but would otherwise throw the answer away — the
    /// record would say "some score, from nobody". <c>source_metadata</c> is the open extension
    /// point (<c>additionalProperties: true</c> in the frozen schema), so the originator NVD
    /// reported is preserved there verbatim, outside the eight-name feed enum that cannot hold it.
    ///
    /// <para>Without this, an analyst asking "who scored this 9.8?" has no answer, and
    /// CLAUDE.md §4.6 requires every input to a risk score be traceable to its source.</para>
    /// </summary>
    [Fact]
    public void An_unattributable_score_still_records_who_did_publish_it()
    {
        var advisory = ParseOne("CVE-2023-33025");

        Assert.NotNull(advisory.SourceMetadataJson);

        using var metadata = System.Text.Json.JsonDocument.Parse(advisory.SourceMetadataJson!);
        Assert.Equal(
            "product-security@qualcomm.com",
            metadata.RootElement.GetProperty("cvssOriginator").GetString());
    }

    /// <summary>
    /// The converse: when NVD did author the score, <c>CvssSource</c> already says so and an
    /// originator key would be redundant noise on every record in the feed.
    /// </summary>
    [Fact]
    public void An_nvd_authored_score_records_no_originator_because_cvss_source_already_says_it()
    {
        var advisory = ParseOne("CVE-2024-0182");

        Assert.Equal(Feeds.Nvd, advisory.CvssSource);
        Assert.Null(advisory.SourceMetadataJson);
    }

    /// <summary>
    /// Primary listed first, so metric ORDER cannot carry this one — it passes only if the family
    /// preference (3.1 before 2.0) is right and the <c>ssvcV203</c> family, which has no
    /// <c>cvssData</c> member at all, is skipped rather than crashed on.
    /// </summary>
    [Fact]
    public void Cvss_v31_is_preferred_over_v2_and_a_family_without_cvss_data_is_skipped()
    {
        var advisory = ParseOne("CVE-2021-44228");

        Assert.Equal(10.0, advisory.CvssBaseScore);
        Assert.Equal("3.1", advisory.CvssVersion);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", advisory.CvssVector);
        Assert.Equal("critical", advisory.Severity);
        Assert.Equal(Feeds.Nvd, advisory.CvssSource);

        // The v2 metric on the same record scores 9.3 — proof the 3.1 branch is what answered.
        Assert.NotEqual(9.3, advisory.CvssBaseScore);
    }

    /// <summary>
    /// No 3.x anywhere on this record. CVSS v2 carries <c>baseSeverity</c> on the metric wrapper
    /// rather than inside <c>cvssData</c>, so this also covers that fallback read.
    /// </summary>
    [Fact]
    public void A_v2_only_record_falls_back_to_v2_and_records_the_version_honestly()
    {
        var advisory = ParseOne("CVE-2015-5477");

        Assert.Equal(7.8, advisory.CvssBaseScore);
        Assert.Equal("2.0", advisory.CvssVersion);
        Assert.Equal("AV:N/AC:L/Au:N/C:N/I:N/A:C", advisory.CvssVector);
        Assert.Equal("high", advisory.Severity);
        Assert.Equal(Feeds.Nvd, advisory.CvssSource);
    }

    // ---------------------------------------------------------------------------------------
    // Identity, description, provenance, cursor
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_advisory_carries_the_cve_id_and_its_english_description()
    {
        var advisory = ParseOne("CVE-2015-5477");

        Assert.Equal(Feeds.Nvd, advisory.Source);
        Assert.Equal("CVE-2015-5477", advisory.ExternalId);
        Assert.StartsWith("named in ISC BIND 9.x before 9.9.7-P2", advisory.Title, StringComparison.Ordinal);
        Assert.Equal(
            new DateTimeOffset(2015, 7, 29, 14, 59, 5, 397, TimeSpan.Zero),
            advisory.PublishedAt);
    }

    /// <summary>
    /// Provenance is what makes a Phase 7 score explainable, so it is asserted field by field
    /// rather than merely counted.
    /// </summary>
    [Fact]
    public void Provenance_names_the_feed_the_record_and_where_it_came_from()
    {
        var advisory = ParseOne("CVE-2024-0182");

        var entry = Assert.Single(advisory.Provenance);
        Assert.Equal(Feeds.Nvd, entry.Source);
        Assert.Equal(RetrievedAt, entry.RetrievedAt);
        Assert.Equal("CVE-2024-0182", entry.SourceRecordId);
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2024-0182", entry.Url);
    }

    /// <summary>The cursor is the newest <c>lastModified</c> in the response, round-trippable.</summary>
    [Fact]
    public void The_cursor_is_the_latest_last_modified_in_the_response()
    {
        var batch = NvdConnector.Parse(Samples.Nvd("CVE-2015-5477"), RetrievedAt);

        Assert.Equal(
            new DateTimeOffset(2026, 6, 17, 0, 29, 11, 660, TimeSpan.Zero),
            DateTimeOffset.Parse(batch.Cursor!, null, System.Globalization.DateTimeStyles.RoundtripKind));
    }

    // ---------------------------------------------------------------------------------------
    // The deliberate asymmetry (ADR 0011)
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// NVD publishes affected version RANGES, which HARD-PROBLEMS #2 rejects as an applicability
    /// basis because they are blind to distro backports. So NVD must never write a fix statement,
    /// however much version data the payload carries — `CVE-2021-44228`'s response is 87 KB, most of
    /// it `configurations`, and none of it may become an affect row.
    /// </summary>
    [Theory]
    [InlineData("CVE-2024-0182")]
    [InlineData("CVE-2021-44228")]
    [InlineData("CVE-2015-5477")]
    [InlineData("CVE-2023-33025")]
    public void Nvd_never_emits_a_fix_statement_a_patch_or_an_overlay(string cve)
    {
        var batch = NvdConnector.Parse(Samples.Nvd(cve), RetrievedAt);

        Assert.Empty(Assert.Single(batch.Advisories).Affects);
        Assert.Empty(batch.Patches);
        Assert.Empty(batch.KevOverlays);
        Assert.Empty(batch.EpssOverlays);
    }
}
