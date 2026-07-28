using PatchManagement.Content.Connectors;

namespace PatchManagement.Content.Tests;

/// <summary>
/// The codename → <c>vendor:version</c> label map. It looks like a lookup table and is easy to treat
/// as cosmetic, but the label is part of a row's IDENTITY: <c>advisory_affects</c> is unique on
/// <c>(advisory_id, package_name, ecosystem, platform)</c>. Getting it wrong does not fail loudly —
/// it silently files the current LTS under a key Phase 6 will not match, and correcting it after an
/// ingest inserts duplicates instead of updating.
/// </summary>
public sealed class DistroReleasesTests
{
    /// <summary>
    /// The map stopped at 24.10 while 26.04 LTS was shipping. LTS releases are what production
    /// fleets actually run, so this is the single most consequential entry in the table.
    /// </summary>
    [Theory]
    [InlineData("resolute", "ubuntu:26.04")]
    [InlineData("noble", "ubuntu:24.04")]
    [InlineData("jammy", "ubuntu:22.04")]
    [InlineData("focal", "ubuntu:20.04")]
    public void Every_supported_lts_maps_to_its_version(string codename, string expected)
    {
        Assert.Equal(expected, DistroReleases.UbuntuPlatform(codename));
    }

    /// <summary>
    /// The interim series matter too — the usn-db still ships notices naming them, and each was
    /// falling through to the raw-codename fallback.
    /// </summary>
    [Theory]
    [InlineData("stonking", "ubuntu:26.10")]
    [InlineData("questing", "ubuntu:25.10")]
    [InlineData("plucky", "ubuntu:25.04")]
    [InlineData("impish", "ubuntu:21.10")]
    [InlineData("disco", "ubuntu:19.04")]
    [InlineData("precise", "ubuntu:12.04")]
    public void Interim_and_historical_series_map_too(string codename, string expected)
    {
        Assert.Equal(expected, DistroReleases.UbuntuPlatform(codename));
    }

    /// <summary>Feeds spell codenames inconsistently; the lookup must not care.</summary>
    [Fact]
    public void Codename_lookup_is_case_insensitive()
    {
        Assert.Equal("ubuntu:26.04", DistroReleases.UbuntuPlatform("Resolute"));
        Assert.Equal("ubuntu:22.04", DistroReleases.UbuntuPlatform("JAMMY"));
    }

    /// <summary>
    /// A series Ubuntu has not announced yet must still ingest. The fallback is deliberately lossy
    /// in LABEL only — never dropping the fix statement and never fabricating a version number that
    /// the vendor has not published.
    ///
    /// <para>No real notice reaches this branch today: all 29 codenames in the live usn-db map to a
    /// published release. It exists for the next series, which is exactly when nobody will be
    /// looking.</para>
    /// </summary>
    [Fact]
    public void An_unannounced_series_falls_back_to_the_raw_codename_rather_than_being_dropped()
    {
        Assert.Equal("ubuntu:notayetreleasedseries", DistroReleases.UbuntuPlatform("notayetreleasedseries"));
    }

    /// <summary>
    /// Debian's half is deliberately untouched by this slice — <c>DebianPlatform</c> is called only
    /// by <c>DebianDsaConnector</c>, whose feed does not exist (its endpoint 404s) and which is
    /// deferred to its own slice. This pins what the map covers TODAY so the DSA slice inherits a
    /// stated starting point rather than a surprise: the pre-stretch suites that
    /// <c>data/DSA/list</c> still carries (woody, sarge, etch, lenny, squeeze, wheezy, jessie) are
    /// absent, and so is the forthcoming <c>forky</c>.
    /// </summary>
    [Fact]
    public void The_debian_map_covers_only_stretch_onwards_and_the_dsa_slice_inherits_that()
    {
        Assert.Equal("debian:12", DistroReleases.DebianPlatform("bookworm"));
        Assert.Equal("debian:13", DistroReleases.DebianPlatform("trixie"));

        // Still unmapped — recorded, not fixed here.
        Assert.Equal("debian:jessie", DistroReleases.DebianPlatform("jessie"));
        Assert.Equal("debian:forky", DistroReleases.DebianPlatform("forky"));
    }
}
