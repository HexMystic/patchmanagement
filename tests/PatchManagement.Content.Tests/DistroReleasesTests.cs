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
    /// Debian's map covered <c>stretch</c>…<c>trixie</c> only until the DSA slice (2026-08-21). The
    /// seven older suites the list still carries accounted for 5,240 of its 8,560 fix statements —
    /// 61% — every one filed under a raw <c>debian:&lt;codename&gt;</c> label rather than
    /// <c>debian:N</c>. All twelve suites appearing in the captured list now map, and
    /// <c>DsaParseTests</c> asserts that no fix statement in the whole file reaches the fallback.
    /// </summary>
    [Theory]
    [InlineData("trixie", "debian:13")]
    [InlineData("bookworm", "debian:12")]
    [InlineData("bullseye", "debian:11")]
    [InlineData("buster", "debian:10")]
    [InlineData("stretch", "debian:9")]
    [InlineData("jessie", "debian:8")]
    [InlineData("wheezy", "debian:7")]
    [InlineData("squeeze", "debian:6")]
    [InlineData("lenny", "debian:5")]
    [InlineData("etch", "debian:4")]
    [InlineData("sarge", "debian:3.1")]
    [InlineData("woody", "debian:3.0")]
    public void Every_suite_the_dsa_list_uses_maps_to_its_version(string codename, string expected)
    {
        Assert.Equal(expected, DistroReleases.DebianPlatform(codename));
    }

    /// <summary>
    /// <c>forky</c> is Debian's announced next release and has no advisory yet. Mapped ahead of its
    /// first one on purpose: the platform label is part of row identity, so adding a series before
    /// its content lands is free and correcting it afterwards is a data migration.
    /// </summary>
    [Fact]
    public void The_announced_next_release_is_mapped_before_its_first_advisory_lands()
    {
        Assert.Equal("debian:14", DistroReleases.DebianPlatform("forky"));
    }

    /// <summary>Debian's lookup must be as case-insensitive as Ubuntu's.</summary>
    [Fact]
    public void Debian_codename_lookup_is_case_insensitive()
    {
        Assert.Equal("debian:12", DistroReleases.DebianPlatform("Bookworm"));
        Assert.Equal("debian:3.0", DistroReleases.DebianPlatform("WOODY"));
    }

    /// <summary>
    /// The fallback survives for a suite Debian has not announced. No real DSA reaches it today —
    /// all twelve codenames in the captured list map — so it exists for the release after forky,
    /// which is exactly when nobody will be looking.
    /// </summary>
    [Fact]
    public void An_unannounced_debian_suite_falls_back_to_the_raw_codename()
    {
        Assert.Equal("debian:notayetreleasedsuite", DistroReleases.DebianPlatform("notayetreleasedsuite"));
    }
}
