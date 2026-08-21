using PatchManagement.Content.Connectors;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// <see cref="DebianDsaConnector.Parse"/> against the whole real Debian DSA list
/// (Samples/PROVENANCE.md — 6,519 advisories, unedited).
///
/// <para>The previous connector pointed at <c>tracker/data/dsa.json</c>, which <b>404s</b>, and
/// parsed a JSON root map Debian serves nowhere. The only canonical source carrying both DSA
/// identifiers and per-suite fixed versions is line-oriented plain text (ADR 0022).</para>
///
/// <para>Everything is asserted BY VALUE, and the fixtures below were chosen from the real file
/// because each defeats a parser that is merely approximately right: an advisory whose suites
/// disagree on the version, a codename that was unmapped until this slice, an id with no revision
/// suffix, an announcement with no package at all, a line whose version is an annotation rather
/// than a version, and an advisory indented with SPACES rather than tabs.</para>
/// </summary>
public sealed class DsaParseTests
{
    private static readonly DateTimeOffset RetrievedAt =
        new(2026, 8, 21, 12, 0, 0, TimeSpan.Zero);

    private static NormalizedBatch? _batch;

    // The capture is 1.1 MB; parse it once for the whole class rather than per test.
    private static NormalizedBatch Batch() =>
        _batch ??= DebianDsaConnector.Parse(Samples.Dsa(), RetrievedAt);

    private static NormalizedAdvisory Advisory(string externalId) =>
        Assert.Single(Batch().Advisories, a => a.ExternalId == externalId);

    private static NormalizedAffect Affect(string externalId, string platform) =>
        Assert.Single(Advisory(externalId).Affects, a => a.Platform == platform);

    // ---------------------------------------------------------------------------------------
    // The whole file parses
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Control, and the headline claim: every advisory in the file is read. A parser that matched
    /// only tab-indented lines, or only ids with a revision suffix, would land under this number
    /// while looking healthy — which is why it is asserted exactly rather than as "not empty".
    /// </summary>
    [Fact]
    public void Every_advisory_in_the_list_is_parsed()
    {
        Assert.Equal(6519, Batch().Advisories.Count);
    }

    [Fact]
    public void The_top_entry_parses_whole()
    {
        var advisory = Advisory("DSA-6455-1");

        Assert.Equal(Feeds.Dsa, advisory.Source);
        // Title is the header remainder exactly as Debian wrote it, package and description both.
        Assert.Equal("chromium - security update", advisory.Title);
        Assert.Equal(new DateTimeOffset(2026, 8, 20, 0, 0, 0, TimeSpan.Zero), advisory.PublishedAt);

        var affect = Assert.Single(advisory.Affects);
        Assert.Equal("chromium", affect.PackageName);
        Assert.Equal("debian:13", affect.Platform);
        Assert.Equal("151.0.7922.169-1~deb13u1", affect.FixedVersion);
    }

    // ---------------------------------------------------------------------------------------
    // The per-suite fan-out — the case a row count cannot catch
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// 1,857 of the 6,519 advisories span more than one suite, and the versions differ per suite.
    /// This is the shape <c>advisory_affects</c> is keyed on platform for: collapsing them would
    /// make Phase 6 tell a bookworm host to install a trixie package. The package name is identical
    /// on both rows, so an assertion on the row COUNT would survive every version being wrong.
    /// </summary>
    [Fact]
    public void One_advisory_states_a_different_fixed_version_per_suite()
    {
        var advisory = Advisory("DSA-6352-1");

        Assert.Equal(
            new SortedSet<string> { "debian:12", "debian:13" },
            new SortedSet<string>(advisory.Affects.Select(a => a.Platform!), StringComparer.Ordinal));

        Assert.Equal("149.0.7827.155-1~deb12u1", Affect("DSA-6352-1", "debian:12").FixedVersion);
        Assert.Equal("149.0.7827.155-1~deb13u1", Affect("DSA-6352-1", "debian:13").FixedVersion);
    }

    /// <summary>
    /// The version is carried RAW (ADR 0011) — the Phase 6 dpkg comparator owns interpretation. The
    /// <c>~deb13u1</c> suffix is the giveaway: a tilde sorts BEFORE everything in dpkg ordering, so
    /// anything that parsed, split or canonicalized this value would change what it means.
    /// </summary>
    [Fact]
    public void The_fixed_version_is_stored_exactly_as_debian_wrote_it()
    {
        var raw = Affect("DSA-6352-1", "debian:13").FixedVersion!;

        Assert.EndsWith("~deb13u1", raw, StringComparison.Ordinal);
        Assert.Contains("149.0.7827.155", raw, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // Codenames — including the seven this slice mapped
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>woody</c> is Debian 3.0 and was unmapped before this slice, so every one of its 871 suite
    /// lines was filed under <c>debian:woody</c> — off the <c>debian:N</c> convention Phase 6 matches
    /// assets on. The list carries twelve codenames and now all twelve map.
    /// </summary>
    [Fact]
    public void The_oldest_suites_map_to_their_version_rather_than_their_codename()
    {
        Assert.Equal("0.9.8-2woody5", Affect("DSA-1105", "debian:3.0").FixedVersion);
    }

    /// <summary>
    /// Control against the map silently regressing: no fix statement in the whole file may carry the
    /// raw <c>debian:&lt;codename&gt;</c> fallback, because every codename the list uses is now mapped.
    /// A single unmapped suite shows up here rather than in Phase 6 six months later.
    /// </summary>
    [Fact]
    public void No_fix_statement_falls_back_to_a_raw_codename()
    {
        var affects = Batch().Advisories.SelectMany(a => a.Affects).ToList();

        Assert.NotEmpty(affects); // control: an empty set would satisfy the assertion below vacuously
        var unmapped = affects
            .Where(a => a.Platform is not null && !System.Text.RegularExpressions.Regex.IsMatch(a.Platform, @"^debian:\d"))
            .Select(a => a.Platform!)
            .Distinct()
            .ToList();

        Assert.Empty(unmapped);
    }

    // ---------------------------------------------------------------------------------------
    // The shapes that are not fix statements
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// 217 headers carry no <c>package - description</c> split at all — they are announcements
    /// ("jessie end-of-life", "PGP/GPG key change notice"). Debian published the id, so the
    /// catalogue records the advisory; there is simply nothing to install.
    ///
    /// <para>This advisory is also one of the 260 indented with SPACES rather than tabs. A parser
    /// anchored on <c>\t</c> drops 525 lines across the file without erroring.</para>
    /// </summary>
    [Fact]
    public void An_announcement_is_an_advisory_with_no_fix_statements()
    {
        var advisory = Advisory("DSA-4205-1");

        Assert.Equal("jessie end-of-life", advisory.Title);
        Assert.Empty(advisory.Affects);
    }

    /// <summary>
    /// 62 suite lines carry an annotation where a version belongs — <c>&lt;not-affected&gt;</c> (55),
    /// <c>&lt;end-of-life&gt;</c> (4), <c>&lt;unfixed&gt;</c> (3). None is a fix statement, and
    /// <c>&lt;not-affected&gt;</c> asserts the OPPOSITE of one: emitting a row with a null version would
    /// have Phase 6 read a fix threshold where Debian said the release was never affected.
    /// </summary>
    [Fact]
    public void An_annotation_where_a_version_belongs_is_not_a_fix_statement()
    {
        Assert.DoesNotContain(Advisory("DSA-3699-1").Affects, a => a.Platform == "debian:8");
    }

    /// <summary>No affect anywhere in the file may carry a null or angle-bracketed version.</summary>
    [Fact]
    public void No_fix_statement_has_a_missing_or_annotated_version()
    {
        var affects = Batch().Advisories.SelectMany(a => a.Affects).ToList();

        Assert.NotEmpty(affects);
        Assert.All(affects, a =>
        {
            Assert.NotNull(a.FixedVersion);
            Assert.DoesNotContain('<', a.FixedVersion!);
        });
    }

    // ---------------------------------------------------------------------------------------
    // Identity, provenance, cursor
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// 450 advisories predate the revision suffix and are plain <c>DSA-NNNN</c>. An id pattern
    /// requiring <c>-N</c> silently drops all of them, which the total count above would catch but
    /// not explain.
    /// </summary>
    [Fact]
    public void An_id_with_no_revision_suffix_is_still_an_advisory()
    {
        Assert.Equal("trac", Advisory("DSA-1209").Title);
    }

    /// <summary>
    /// Revisions are separate advisories with distinct ids, exactly as USN treats <c>-2</c>. 179 DSA
    /// numbers carry more than one revision, and <c>advisories(source, external_id)</c> is unique, so
    /// conflating them would drop content.
    /// </summary>
    [Fact]
    public void Each_revision_of_an_advisory_is_its_own_record()
    {
        var revisions = Batch().Advisories
            .Select(a => a.ExternalId)
            .Where(id => id.StartsWith("DSA-6197-", StringComparison.Ordinal))
            .ToList();

        Assert.Equal(3, revisions.Count);
    }

    /// <summary>
    /// Debian publishes no normalized severity band, so the connector must not invent one — an
    /// invented band would feed a Phase 7 risk score that nothing in the source supports
    /// (HARD-PROBLEMS #8). Same posture as USN.
    /// </summary>
    [Fact]
    public void Severity_stays_unknown_because_debian_does_not_publish_one()
    {
        Assert.All(Batch().Advisories, a => Assert.Equal("unknown", a.Severity));
    }

    [Fact]
    public void The_cves_an_advisory_fixes_are_preserved_in_source_metadata()
    {
        using var metadata = System.Text.Json.JsonDocument.Parse(Advisory("DSA-6453-1").SourceMetadataJson!);

        Assert.Equal(
            new[] { "CVE-2026-5917", "CVE-2026-53583", "CVE-2026-53584", "CVE-2026-53585", "CVE-2026-53586", "CVE-2026-53587" },
            metadata.RootElement.GetProperty("cves").EnumerateArray().Select(e => e.GetString()).ToArray());
    }

    /// <summary>
    /// Provenance cites the canonical security-tracker page even though the bytes came from salsa.
    /// ADR 0022 keeps citation and transport separate: an analyst auditing a finding should land on
    /// Debian's own tracker, not a git forge raw URL.
    /// </summary>
    [Fact]
    public void Provenance_names_the_feed_the_advisory_and_the_canonical_tracker_page()
    {
        var entry = Assert.Single(Advisory("DSA-6455-1").Provenance);

        Assert.Equal(Feeds.Dsa, entry.Source);
        Assert.Equal(RetrievedAt, entry.RetrievedAt);
        Assert.Equal("DSA-6455-1", entry.SourceRecordId);
        Assert.Equal("https://security-tracker.debian.org/tracker/DSA-6455-1", entry.Url);
    }

    /// <summary>
    /// The cursor is the newest advisory's FULL id, revision suffix included. The file is ordered by
    /// date and revisions are prepended, so a re-issued old advisory appears ABOVE this cursor and is
    /// picked up rather than missed — which a date cursor (day-granular, 3 advisories share the
    /// newest date) or a count could not promise.
    /// </summary>
    [Fact]
    public void The_cursor_is_the_newest_advisorys_full_id()
    {
        Assert.Equal("DSA-6455-1", Batch().Cursor);
    }

    /// <summary>A DSA is both advisory and patch — "upgrade to the stated version" is installable.</summary>
    [Fact]
    public void Each_advisory_also_produces_a_patch_keyed_on_the_same_id()
    {
        var patch = Assert.Single(Batch().Patches, p => p.VendorId == "DSA-6455-1");

        Assert.Equal(Feeds.Dsa, patch.Source);
        Assert.Equal("Security Updates", patch.Classification);
        Assert.False(patch.Reversible);
        Assert.False(patch.RequiresReboot);
        Assert.Empty(patch.Supersedes);
    }

    /// <summary>Every Debian fix is a backported deb — the case HARD-PROBLEMS #2 exists for.</summary>
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

    [Fact]
    public void Dsa_emits_no_overlays()
    {
        Assert.Empty(Batch().KevOverlays);
        Assert.Empty(Batch().EpssOverlays);
    }

    // ---------------------------------------------------------------------------------------
    // Fail loudly — ADR 0022's mitigation (a)
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A document with content but no parseable advisory header is a format change — salsa moving
    /// the file, a login page, an error body. It must fail the sync rather than return an empty
    /// batch for ContentSyncService to record as <c>ok</c>.
    /// </summary>
    [Fact]
    public void A_document_with_no_parseable_advisory_throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => DebianDsaConnector.Parse("<!DOCTYPE html><html><body>404</body></html>", RetrievedAt));

        Assert.Contains("dsa", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>An empty document is empty — a different fact from a broken one.</summary>
    [Fact]
    public void A_genuinely_empty_document_is_accepted_as_empty()
    {
        var batch = DebianDsaConnector.Parse(string.Empty, RetrievedAt);

        Assert.Empty(batch.Advisories);
        Assert.Empty(batch.Patches);
        Assert.Null(batch.Cursor);
    }
}
