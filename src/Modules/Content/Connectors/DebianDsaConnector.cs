using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// Debian Security Advisory connector. Debian is an independent distro — no USN/RHSA covers it — so
/// <c>dsa</c> is its own publisher in the frozen vocabulary, required by the lab's Debian 12 box
/// (HARD-PROBLEMS #2/#3). A DSA is both an advisory and its applicability source, mirroring USN: it
/// yields a <see cref="NormalizedAdvisory"/> (source = <c>dsa</c>) with per-suite fix statements and
/// a <see cref="NormalizedPatch"/> (source = <c>dsa</c>) — "upgrade to the stated package version".
///
/// <para><b>Rewritten 2026-08-21 against the real captured list.</b> The previous version pointed at
/// <c>security-tracker.debian.org/tracker/data/dsa.json</c>, which <b>404s</b>, and parsed a JSON
/// root map of <c>DSA-id → {releases: {suite: {packages: {pkg: {version}}}}}</c> that Debian serves
/// at no URL — the same invented-envelope defect recorded for <c>rhsa</c> and <c>msrc</c>, and the
/// last of the three. <b>Debian publishes no structured feed carrying both DSA identifiers and
/// per-suite fixed versions</b>; the source is salsa's raw plain-text <c>data/DSA/list</c>, accepted
/// with its stability risk named in <b>ADR 0022</b> (which lives on <c>main</c>; this branch predates
/// the file). The shape checks below are that ADR's binding mitigation: this parser must fail loudly
/// rather than hand back an empty batch for the sync to record as <c>ok</c>.</para>
///
/// <para><b>The format, measured across the whole 1.1 MB file rather than assumed.</b> An advisory is
/// an unindented header followed by indented detail lines:</para>
/// <code>
/// [20 Aug 2026] DSA-6455-1 chromium - security update
///     {CVE-2026-76033 CVE-2026-76034 …}
///     [trixie] - chromium 151.0.7922.169-1~deb13u1
/// </code>
/// <list type="bullet">
///   <item><b>Indentation is mixed</b> — 14,846 lines use a tab and <b>525 use spaces</b>. Anchoring
///     on <c>\t</c> drops 260 advisories' detail without erroring.</item>
///   <item><b>217 headers carry no <c>package - description</c> split</b> — they are announcements
///     ("jessie end-of-life"). They are advisories with nothing to install.</item>
///   <item><b>450 ids predate the revision suffix</b> and are plain <c>DSA-NNNN</c>.</item>
///   <item><b>62 suite lines carry an annotation where a version belongs</b> —
///     <c>&lt;not-affected&gt;</c>, <c>&lt;end-of-life&gt;</c>, <c>&lt;unfixed&gt;</c>. None is a fix
///     statement, and <c>&lt;not-affected&gt;</c> asserts the opposite of one.</item>
/// </list>
///
/// <para><b>The cursor is the newest advisory's full id, and it is emitted but not consumed.</b> The
/// file is ordered by DATE, not by id — revisions are re-inserted at the top, so 179 DSA numbers
/// carry several revisions and the id order inverts 181 times. A full id (<c>DSA-6455-1</c>) is
/// therefore the only exact resume point: a re-issued old advisory appears ABOVE it and is picked up
/// rather than missed, which a day-granular date cursor could not promise. Using it to limit
/// parsing is incrementality — Phase 5 criterion (b) — and is deliberately not built here.</para>
///
/// Fixes are <c>backported = true</c> (Debian's <c>~debNuM</c> suffix is a backport into the frozen
/// upstream version). The version is carried RAW; only the suite codename is mapped to
/// <c>debian:NN</c> (ADR 0011).
/// </summary>
public sealed class DebianDsaConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint =
        "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list";

    /// <summary><c>[20 Aug 2026] DSA-6455-1 chromium - security update</c>. The remainder is optional.</summary>
    private static readonly Regex Header = new(
        @"^\[(?<date>\d{1,2} \w{3} \d{4})\]\s+(?<id>DSA-\d+(?:-\d+)?)\s*(?<rest>.*)$",
        RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    /// <summary><c>[trixie] - chromium 151.0.7922.169-1~deb13u1</c>, tab- or space-indented.</summary>
    private static readonly Regex SuiteLine = new(
        @"^[\t ]+\[(?<codename>[^\]]+)\]\s*-\s*(?<package>\S+)\s*(?<version>.*)$",
        RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    public string Kind => Feeds.Dsa;

    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        var uri = new Uri(state.Endpoint ?? DefaultEndpoint);
        var text = await fetcher.GetStringAsync(uri, ct);
        return Parse(text, DateTimeOffset.UtcNow);
    }

    public static NormalizedBatch Parse(string text, DateTimeOffset retrievedAt)
    {
        var advisories = new List<NormalizedAdvisory>();
        var patches = new List<NormalizedPatch>();

        Builder? current = null;
        var sawContent = false;

        foreach (var line in text.Split('\n'))
        {
            var stripped = line.TrimEnd('\r');
            if (stripped.Trim().Length == 0)
                continue;

            sawContent = true;

            if (stripped[0] is not ('\t' or ' '))
            {
                Flush(current, advisories, patches, retrievedAt);
                current = null;

                if (Header.Match(stripped) is { Success: true } header)
                    current = new Builder(
                        header.Groups["id"].Value,
                        header.Groups["rest"].Value.Trim(),
                        ParseDate(header.Groups["date"].Value));

                continue;
            }

            if (current is null)
                continue;

            var detail = stripped.TrimStart('\t', ' ');

            if (detail.StartsWith('{'))
            {
                current.Cves.AddRange(
                    detail.Trim('{', '}').Split(' ', StringSplitOptions.RemoveEmptyEntries));
                continue;
            }

            if (SuiteLine.Match(stripped) is { Success: true } suite)
                current.AddSuite(
                    suite.Groups["codename"].Value,
                    suite.Groups["package"].Value,
                    suite.Groups["version"].Value.Trim());

            // Anything else (NOTE:, TODO:, free commentary) carries no applicability fact.
        }

        Flush(current, advisories, patches, retrievedAt);

        // A document with content but no advisory in it is a format change — salsa moving the file,
        // an error body, a login page. Refusing here is what stops ContentSyncService recording an
        // empty catalogue as a successful sync (ADR 0022 mitigation (a)).
        if (sawContent && advisories.Count == 0)
            throw new InvalidOperationException(
                "The dsa list carried content but no parseable advisory header. The source's format "
                + "has changed — refusing to report an empty sync as success.");

        return new NormalizedBatch
        {
            Advisories = advisories,
            Patches = patches,
            // The file is newest-first, so the first advisory parsed is the newest. Its FULL id
            // (revision suffix included) is unique and is the exact resume point — see the class doc.
            Cursor = advisories.Count > 0 ? advisories[0].ExternalId : null,
        };
    }

    private static void Flush(
        Builder? builder,
        List<NormalizedAdvisory> advisories,
        List<NormalizedPatch> patches,
        DateTimeOffset retrievedAt)
    {
        if (builder is null)
            return;

        var provenance = new[]
        {
            new ProvenanceEntry(
                Feeds.Dsa, retrievedAt, SourceRecordId: builder.Id,
                // The bytes come from salsa, but an analyst auditing a finding should land on
                // Debian's own tracker page. ADR 0022 keeps citation and transport separate.
                Url: $"https://security-tracker.debian.org/tracker/{builder.Id}"),
        };

        advisories.Add(new NormalizedAdvisory
        {
            Source = Feeds.Dsa,
            ExternalId = builder.Id,
            Title = builder.Title.Length > 0 ? builder.Title : builder.Id,
            // Debian publishes no normalized severity band; leave it honest rather than guess
            // (HARD-PROBLEMS #8). Same posture as USN.
            Severity = "unknown",
            PublishedAt = builder.PublishedAt,
            SourceMetadataJson = builder.Cves.Count > 0
                ? JsonSerializer.Serialize(new { cves = builder.Cves.ToArray() })
                : null,
            Provenance = provenance,
            Affects = builder.Affects,
        });

        patches.Add(new NormalizedPatch
        {
            Source = Feeds.Dsa,
            VendorId = builder.Id,
            Title = builder.Title.Length > 0 ? builder.Title : builder.Id,
            // apt can revert a package, but Debian never asserted rollback safety, and a DSA carries
            // no reboot flag. False is the honest answer for each.
            Reversible = false,
            RequiresReboot = false,
            Classification = "Security Updates",
            PublishedAt = builder.PublishedAt,
            Provenance = provenance,
        });
    }

    private static DateTimeOffset? ParseDate(string raw) =>
        DateTimeOffset.TryParseExact(
            raw, "d MMM yyyy", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;

    /// <summary>Accumulates one advisory's lines until the next header, or end of file.</summary>
    private sealed class Builder(string id, string title, DateTimeOffset? publishedAt)
    {
        private readonly HashSet<(string Package, string Platform)> _seen = [];

        public string Id { get; } = id;
        public string Title { get; } = title;
        public DateTimeOffset? PublishedAt { get; } = publishedAt;
        public List<string> Cves { get; } = [];
        public List<NormalizedAffect> Affects { get; } = [];

        public void AddSuite(string codename, string package, string version)
        {
            // An annotation (<not-affected>, <unfixed>, <end-of-life>) sits where a version belongs
            // on 62 lines. None is a fix statement — <not-affected> states the OPPOSITE of one, and
            // a row with a null version would have Phase 6 read it as a fix threshold.
            if (version.Length == 0 || version.StartsWith('<'))
                return;

            var platform = DistroReleases.DebianPlatform(codename);

            // advisory_affects is unique on (advisory, package, ecosystem, platform), so a repeated
            // pair would be collapsed by the store anyway and the reported count would overstate.
            if (!_seen.Add((package, platform)))
                return;

            Affects.Add(new NormalizedAffect(
                PackageName: package,
                Ecosystem: Ecosystems.Deb,
                Platform: platform,
                FixedVersion: version,
                Backported: true));
        }
    }
}
