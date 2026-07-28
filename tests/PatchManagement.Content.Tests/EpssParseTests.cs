using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// <see cref="EpssConnector.Parse"/> against the whole, unedited FIRST EPSS response
/// (Samples/PROVENANCE.md — 387 bytes, captured verbatim).
///
/// <para>Like KEV, EPSS is an OVERLAY: it scores an existing CVE and never publishes one.</para>
/// </summary>
public sealed class EpssParseTests
{
    private static readonly DateTimeOffset RetrievedAt =
        new(2026, 7, 28, 12, 0, 0, TimeSpan.Zero);

    private static EpssOverlay Overlay(string cve) =>
        Assert.Single(
            EpssConnector.Parse(Samples.Epss(), RetrievedAt).EpssOverlays,
            o => o.CveId == cve);

    /// <summary>
    /// The API sends these as JSON STRINGS — <c>"epss": "0.859740000"</c>, not a number. A reader
    /// that only accepts <see cref="System.Text.Json.JsonValueKind.Number"/> yields null, and
    /// <c>Parse</c> then <c>continue</c>s past the record: the failure mode is not an exception but
    /// an EMPTY BATCH reported as a successful sync — every score silently dropped.
    /// </summary>
    [Fact]
    public void Scores_arrive_as_json_strings_and_are_still_read_as_numbers()
    {
        Assert.Contains("\"epss\":\"0.859740000\"", Samples.Epss(), StringComparison.Ordinal);

        Assert.Equal(0.85974, Overlay("CVE-2024-3094").Score, precision: 10);
    }

    /// <summary>
    /// EPSS publishes probabilities in [0,1], NOT percentages. <c>advisories.epss_score</c> is
    /// CHECK-constrained to [0,1], so a stray ×100 would be rejected by the database — but it would
    /// also silently inflate every Phase 7 risk input up to that point.
    /// </summary>
    [Fact]
    public void Probabilities_are_carried_unscaled_never_as_percentages()
    {
        var overlay = Overlay("CVE-2021-44228");

        Assert.Equal(0.99999, overlay.Score, precision: 10);
        Assert.Equal(1.0, overlay.Percentile!.Value, precision: 10);

        Assert.InRange(overlay.Score, 0.0, 1.0);
        Assert.InRange(overlay.Percentile!.Value, 0.0, 1.0);
    }

    [Fact]
    public void Percentile_is_read_independently_of_the_score()
    {
        var overlay = Overlay("CVE-2015-5477");

        Assert.Equal(0.91284, overlay.Score, precision: 10);
        Assert.Equal(0.99799, overlay.Percentile!.Value, precision: 10);
    }

    /// <summary>The model date is a plain date, anchored at midnight UTC rather than local time.</summary>
    [Fact]
    public void The_model_date_becomes_midnight_utc()
    {
        var overlay = Overlay("CVE-2024-3094");

        Assert.Equal(new DateTimeOffset(2026, 7, 28, 0, 0, 0, TimeSpan.Zero), overlay.ScoredAt);
        Assert.Equal(TimeSpan.Zero, overlay.ScoredAt!.Value.Offset);
    }

    [Fact]
    public void Provenance_names_the_feed_and_the_scored_cve()
    {
        var entry = Overlay("CVE-2015-5477").Provenance;

        Assert.Equal(Feeds.Epss, entry.Source);
        Assert.Equal(RetrievedAt, entry.RetrievedAt);
        Assert.Equal("CVE-2015-5477", entry.SourceRecordId);
        Assert.Equal("https://api.first.org/data/v1/epss", entry.Url);
    }

    /// <summary>Scores are republished daily, so the model date is the incremental bookmark.</summary>
    [Fact]
    public void The_cursor_is_the_model_date()
    {
        Assert.Equal("2026-07-28", EpssConnector.Parse(Samples.Epss(), RetrievedAt).Cursor);
    }

    /// <summary>The asymmetry: EPSS decorates an advisory, it never creates one.</summary>
    [Fact]
    public void Epss_emits_overlays_only_never_an_advisory_or_a_patch()
    {
        var batch = EpssConnector.Parse(Samples.Epss(), RetrievedAt);

        Assert.Empty(batch.Advisories);
        Assert.Empty(batch.Patches);
        Assert.Empty(batch.KevOverlays);

        Assert.Equal(
            new SortedSet<string> { "CVE-2024-3094", "CVE-2021-44228", "CVE-2015-5477" },
            new SortedSet<string>(batch.EpssOverlays.Select(o => o.CveId), StringComparer.Ordinal));
    }
}
