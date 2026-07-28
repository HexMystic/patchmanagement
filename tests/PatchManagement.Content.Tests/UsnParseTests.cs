using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// <see cref="UsnConnector.Parse"/> against real notices from the usn-db map
/// (Samples/PROVENANCE.md — two complete entries, unedited, out of 7,678).
///
/// <para>USN is the first feed in this module that emits FIX STATEMENTS, so this is the first test
/// of the <c>advisory_affects</c> shape Phase 6's comparator consumes. Both fixtures were chosen so
/// that a row COUNT cannot stand in for a row VALUE: <c>8465-1</c> ships the same package name on
/// three releases at three different versions, so counting rows would pass while every version was
/// wrong.</para>
/// </summary>
public sealed class UsnParseTests
{
    private static readonly DateTimeOffset RetrievedAt =
        new(2026, 7, 29, 12, 0, 0, TimeSpan.Zero);

    private static NormalizedBatch Batch() => UsnConnector.Parse(Samples.Usn(), RetrievedAt);

    private static NormalizedAdvisory Advisory(string externalId) =>
        Assert.Single(Batch().Advisories, a => a.ExternalId == externalId);

    private static NormalizedAffect Affect(string externalId, string platform) =>
        Assert.Single(Advisory(externalId).Affects, a => a.Platform == platform);

    // ---------------------------------------------------------------------------------------
    // The per-release fan-out — the point of this slice
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// One advisory, one package, three supported releases, three DIFFERENT fixed versions. This is
    /// the shape ADR 0011 exists for and the reason `advisory_affects` is keyed on platform: a
    /// single USN legitimately states a different fix per release, and collapsing them would make
    /// Phase 6 tell a 22.04 host to install a 24.04 package.
    /// </summary>
    [Fact]
    public void One_notice_states_a_different_fixed_version_for_every_release_it_covers()
    {
        var advisory = Advisory("USN-8465-1");

        Assert.Equal(
            new SortedSet<string> { "ubuntu:22.04", "ubuntu:24.04", "ubuntu:26.04" },
            new SortedSet<string>(advisory.Affects.Select(a => a.Platform!), StringComparer.Ordinal));

        // Asserted by value per platform. The package name is identical on all three rows, so a
        // count assertion would survive every version being wrong.
        Assert.Equal("2.1.5-1ubuntu0.1~esm1", Affect("USN-8465-1", "ubuntu:22.04").FixedVersion);
        Assert.Equal("2.2.1-3ubuntu0.1~esm1", Affect("USN-8465-1", "ubuntu:24.04").FixedVersion);
        Assert.Equal("2.2.1-4ubuntu0.1~esm1", Affect("USN-8465-1", "ubuntu:26.04").FixedVersion);
    }

    /// <summary>
    /// <c>resolute</c> is Ubuntu 26.04 LTS. It was absent from <c>DistroReleases</c>, so every fix
    /// statement for the current LTS was labelled <c>ubuntu:resolute</c> — off the
    /// <c>ubuntu:&lt;version&gt;</c> convention the rest of the catalogue and Phase 6 match on.
    /// </summary>
    [Fact]
    public void The_current_lts_is_labelled_by_version_not_by_codename()
    {
        var affect = Affect("USN-8465-1", "ubuntu:26.04");

        Assert.Equal("mina2", affect.PackageName);
        Assert.Equal("2.2.1-4ubuntu0.1~esm1", affect.FixedVersion);
    }

    /// <summary>
    /// The same gap, one release apart and years older: <c>disco</c> is 19.04. Its fixed version
    /// differs from bionic's only in the release suffix, which is exactly the distinction a
    /// backport-aware comparator has to make.
    /// </summary>
    [Fact]
    public void An_older_unmapped_release_is_also_labelled_by_version()
    {
        Assert.Equal("1.0.10-1ubuntu0.18.04.1", Affect("USN-4123-1", "ubuntu:18.04").FixedVersion);
        Assert.Equal("1.0.10-1ubuntu0.19.04.2", Affect("USN-4123-1", "ubuntu:19.04").FixedVersion);
    }

    /// <summary>
    /// Ubuntu backports fixes into the distro package version rather than bumping upstream, which
    /// is precisely the case that makes naive upstream comparison produce mass false positives
    /// (HARD-PROBLEMS #2). Every row must say so, and every row is a deb.
    /// </summary>
    [Fact]
    public void Every_fix_statement_is_a_backported_deb()
    {
        var affects = Batch().Advisories.SelectMany(a => a.Affects).ToList();

        Assert.NotEmpty(affects);
        Assert.All(affects, a =>
        {
            Assert.Equal(Ecosystems.Deb, a.Ecosystem);
            Assert.True(a.Backported, $"{a.PackageName} on {a.Platform} is not marked backported.");
        });
    }

    /// <summary>
    /// The version string is carried RAW (ADR 0011) — the Phase 6 comparator owns interpretation.
    /// The `~esm1` suffix is the giveaway: anything that parsed, split or canonicalized the value
    /// would drop or reorder it.
    /// </summary>
    [Fact]
    public void The_fixed_version_is_stored_exactly_as_the_source_wrote_it()
    {
        var raw = Affect("USN-8465-1", "ubuntu:26.04").FixedVersion!;

        Assert.EndsWith("~esm1", raw, StringComparison.Ordinal);
        Assert.Contains("2.2.1-4ubuntu0.1", raw, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // Identity — one source field becomes three different strings
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The feed writes ids unprefixed (<c>"8465-1"</c>). The advisory's <c>external_id</c> must be
    /// the canonical <c>USN-8465-1</c>, the provenance must cite the id **as the source wrote it**,
    /// and the URL must use the prefixed form. Three strings, one field — easy to conflate, and a
    /// conflation would either break the ubuntu.com link or corrupt the advisory key.
    /// </summary>
    [Fact]
    public void The_unprefixed_feed_id_becomes_a_prefixed_external_id_but_provenance_keeps_the_original()
    {
        var advisory = Advisory("USN-8465-1");
        var entry = Assert.Single(advisory.Provenance);

        Assert.Equal("8465-1", entry.SourceRecordId);
        Assert.Equal("https://ubuntu.com/security/notices/USN-8465-1", entry.Url);
        Assert.Equal(Feeds.Usn, entry.Source);
        Assert.Equal(RetrievedAt, entry.RetrievedAt);
    }

    [Fact]
    public void The_advisory_carries_the_notice_title_and_publication_time()
    {
        var advisory = Advisory("USN-8465-1");

        Assert.Equal(Feeds.Usn, advisory.Source);
        Assert.Equal("Apache MINA vulnerabilities", advisory.Title);
        Assert.Equal(
            DateTimeOffset.FromUnixTimeMilliseconds(1782228956329),
            advisory.PublishedAt);
    }

    /// <summary>
    /// USN publishes no normalized severity band, so the connector must not invent one — an
    /// invented band would feed a Phase 7 risk score that nothing in the source supports
    /// (HARD-PROBLEMS #8).
    /// </summary>
    [Fact]
    public void Severity_stays_unknown_because_usn_does_not_publish_one()
    {
        Assert.Equal("unknown", Advisory("USN-8465-1").Severity);
        Assert.Equal("unknown", Advisory("USN-4123-1").Severity);
    }

    /// <summary>The CVEs a notice fixes ride in the open extension point, not in a typed column.</summary>
    [Fact]
    public void The_notices_cves_are_preserved_in_source_metadata()
    {
        using var metadata = System.Text.Json.JsonDocument.Parse(Advisory("USN-4123-1").SourceMetadataJson!);

        Assert.Equal(
            new[] { "CVE-2019-13173" },
            metadata.RootElement.GetProperty("cves").EnumerateArray().Select(e => e.GetString()).ToArray());
    }

    // ---------------------------------------------------------------------------------------
    // Patch side, cursor, and what USN never emits
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A USN is both advisory and patch — "upgrade to this exact version" is an installable action.
    /// Both flags default false: apt can revert a package, but the vendor never asserted rollback
    /// safety, and Ubuntu does not flag reboot per notice. False is the safe answer for each
    /// (rollback stays gated off; no maintenance window is under-estimated).
    /// </summary>
    [Fact]
    public void Each_notice_also_produces_a_patch_keyed_on_the_same_id()
    {
        var patch = Assert.Single(Batch().Patches, p => p.VendorId == "USN-8465-1");

        Assert.Equal(Feeds.Usn, patch.Source);
        Assert.Equal("Apache MINA vulnerabilities", patch.Title);
        Assert.Equal("Security Updates", patch.Classification);
        Assert.False(patch.Reversible);
        Assert.False(patch.RequiresReboot);
        Assert.Empty(patch.Supersedes);
    }

    /// <summary>The newest notice timestamp is the incremental bookmark.</summary>
    [Fact]
    public void The_cursor_is_the_newest_notice_timestamp()
    {
        Assert.Equal("1782228956.329703", Batch().Cursor);
    }

    /// <summary>USN publishes fixes, never exploitation or scoring overlays.</summary>
    [Fact]
    public void Usn_emits_no_overlays()
    {
        var batch = Batch();

        Assert.Empty(batch.KevOverlays);
        Assert.Empty(batch.EpssOverlays);

        Assert.Equal(
            new SortedSet<string> { "USN-8465-1", "USN-4123-1" },
            new SortedSet<string>(batch.Advisories.Select(a => a.ExternalId), StringComparer.Ordinal));
    }
}
