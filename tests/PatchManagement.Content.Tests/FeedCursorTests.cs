using PatchManagement.Content.Connectors;

namespace PatchManagement.Content.Tests;

/// <summary>
/// The cursor contract ADR 0022 said had to be restated rather than papered over.
///
/// <para>Two mechanisms share one <c>content_sources.cursor</c> column: a feed's own bookmark (an
/// NVD timestamp, a KEV catalogue version, a DSA id) and, for the whole-file feeds, the HTTP
/// validators that let a GET be conditional. The encoding has to carry both WITHOUT changing the
/// value the six non-conditional feeds already persist — otherwise this slice silently rewrites
/// every stored cursor in the catalogue and the first run after deploy re-ingests everything.</para>
/// </summary>
public sealed class FeedCursorTests
{
    /// <summary>
    /// The compatibility guarantee, stated as an equality rather than a shape: with no validators
    /// the cursor IS the bare semantic string. <c>DsaParseTests</c> pins <c>"DSA-6455-1"</c> and
    /// <c>UsnParseTests</c> pins <c>"1782228956.329703"</c>; those values must survive a round trip
    /// through this codec untouched.
    /// </summary>
    [Theory]
    [InlineData("DSA-6455-1")]
    [InlineData("1782228956.329703")]
    [InlineData("2026-Aug")]
    [InlineData("e1a000e0-066b-497a-ba62-246d4af43e55")]
    public void A_cursor_with_no_validators_formats_to_the_bare_semantic_string(string semantic)
    {
        Assert.Equal(semantic, new FeedCursor(semantic).Format());
    }

    /// <summary>The other direction: every cursor already in the database reads back as itself.</summary>
    [Fact]
    public void A_legacy_bare_cursor_reads_back_as_its_semantic_value()
    {
        var read = FeedCursor.Read("2026.07.27");

        Assert.Equal("2026.07.27", read.Semantic);
        Assert.False(read.HasValidators);
    }

    /// <summary>Validators survive the round trip, which is the whole point of the second form.</summary>
    [Fact]
    public void A_cursor_with_validators_round_trips_both_halves()
    {
        var lastModified = new DateTimeOffset(2026, 7, 27, 19, 0, 15, TimeSpan.Zero);

        var read = FeedCursor.Read(new FeedCursor("2026.07.27", "\"abc\"", lastModified).Format());

        Assert.Equal("2026.07.27", read.Semantic);
        Assert.Equal("\"abc\"", read.ETag);
        Assert.Equal(lastModified, read.LastModified);
    }

    /// <summary>
    /// An empty cursor must stay NULL in the column rather than becoming a JSON object that means
    /// "nothing", which a later reader would have to know to unwrap.
    /// </summary>
    [Fact]
    public void An_empty_cursor_formats_to_null()
    {
        Assert.Null(FeedCursor.None.Format());
    }

    /// <summary>
    /// A cursor that cannot be decoded must cost one full re-fetch, not a failed sync. The failure
    /// path holds the cursor it could not read, so throwing here would wedge the feed permanently:
    /// every subsequent run would re-read the same unreadable value and fail the same way.
    /// </summary>
    [Fact]
    public void An_undecodable_cursor_degrades_to_semantic_rather_than_throwing()
    {
        var read = FeedCursor.Read("{not actually json");

        Assert.Equal("{not actually json", read.Semantic);
        Assert.False(read.HasValidators);
    }
}
