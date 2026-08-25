using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// Red Hat Security Advisory connector. An RHSA is an advisory + its rpm applicability source: it
/// states the exact fixed NEVR per RHEL product, which is what HARD-PROBLEMS #2 requires (RHEL
/// backports fixes into the same upstream version with a new release, so <c>backported = true</c>).
/// Produces a <see cref="NormalizedAdvisory"/> (source = <c>rhsa</c>) with rpm fix statements and a
/// <see cref="NormalizedPatch"/> (source = <c>rhsa</c>).
///
/// <para><b>Rewritten 2026-08-21 against a real captured payload.</b> The previous parser expected a
/// root OBJECT with an <c>advisories</c> array and per-advisory <c>cvss3</c>/<c>affected[]</c>
/// members. Red Hat serves a root ARRAY of summary objects, so <c>JsonHelpers.Array</c> — which
/// requires an object receiver — returned <c>[]</c>, the batch was empty, and
/// <c>ContentSyncService</c> recorded <c>status = 'ok'</c> with the cursor advanced. An operator saw
/// a green sync over an empty catalogue: this project's "reports success while untrue" hazard
/// (ADR 0016). The shape checks below exist so that failure mode cannot return.</para>
///
/// <para>The summary carries no title and no CVSS, so <see cref="NormalizedAdvisory.Title"/> falls
/// back to the advisory id and the CVSS members stay null rather than being invented. The full CSAF
/// document behind each <c>resource_url</c> carries more, but fetching it would turn one sync into
/// thousands of requests for fields the applicability path does not need.</para>
///
/// RHSA also serves Rocky/Alma, which rebuild RHEL content (phase-1 Group B): those hosts are
/// assessed against <c>rhsa</c> until native RLSA/ALSA precision is ever needed (a deferred,
/// additive Phase-5/6 decision — never a change to the frozen vocabulary).
///
/// The NEVR (e.g. <c>1:2.14.18-3.el9_8.1</c>) is carried RAW; the RPM comparator (Phase 6) owns
/// epoch and <c>rpmvercmp</c> semantics (ADR 0011, HARD-PROBLEMS #3).
/// </summary>
public sealed class RhsaConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint =
        "https://access.redhat.com/hydra/rest/securitydata/csaf.json";

    public string Kind => Feeds.Rhsa;

    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        var uri = FeedUri.With(
            new Uri(state.Endpoint ?? DefaultEndpoint),
            ("after", After(FeedCursor.Read(state.Cursor).Semantic)));

        var json = await fetcher.GetStringAsync(uri, ct);
        var batch = Parse(json, DateTimeOffset.UtcNow);

        // Hold rather than null: a narrowed window that returned nothing is the normal quiet case,
        // and dropping the cursor would re-open the whole catalogue on the next run.
        return batch.Cursor is null ? batch with { Cursor = state.Cursor } : batch;
    }

    /// <summary>
    /// Red Hat's <c>after</c> filter is DATE-granular, so the cursor's time half is dropped. That
    /// makes the window inclusive of the cursor's own day and re-reads it — which is the safe
    /// direction: the upserts are idempotent, and rounding the other way would skip advisories
    /// released later on the same day as the last one ingested.
    /// </summary>
    private static string? After(string? cursor) =>
        DateTimeOffset.TryParse(
            cursor, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var since)
            ? since.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : null;

    public static NormalizedBatch Parse(string json, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Shape check, not a tolerant read. This is the exact defect being fixed: the old parser
        // asked an array for an object member and was handed an empty sequence in silence.
        if (root.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException(
                $"The rhsa feed must be a JSON array of advisories; received {root.ValueKind}. "
                + "The endpoint's format has changed — refusing to report an empty sync as success.");

        var advisories = new List<NormalizedAdvisory>();
        var patches = new List<NormalizedPatch>();
        DateTimeOffset? maxReleased = null;
        var entries = 0;

        foreach (var adv in root.EnumerateArray())
        {
            entries++;

            var id = adv.StringOrNull("RHSA");
            if (string.IsNullOrEmpty(id))
                continue;

            var released = adv.DateTimeOffsetOrNull("released_on");
            if (released is { } r && (maxReleased is null || r > maxReleased))
                maxReleased = r;

            var cves = adv.Array("CVEs").Select(c => c.GetString()).Where(c => c is not null).ToArray();

            var provenance = new[]
            {
                new ProvenanceEntry(
                    Feeds.Rhsa, retrievedAt, SourceRecordId: id,
                    Url: $"https://access.redhat.com/errata/{id}"),
            };

            advisories.Add(new NormalizedAdvisory
            {
                Source = Feeds.Rhsa,
                // The summary payload has no title member. The id is the honest fallback — a
                // fabricated title would be a value no Red Hat page carries.
                ExternalId = id,
                Title = id,
                Severity = MapSeverity(adv.StringOrNull("severity")),
                PublishedAt = released,
                SourceMetadataJson = cves.Length > 0 ? JsonSerializer.Serialize(new { cves }) : null,
                Provenance = provenance,
                Affects = ReadAffects(adv).ToList(),
            });

            patches.Add(new NormalizedPatch
            {
                Source = Feeds.Rhsa,
                VendorId = id,
                Title = id,
                Reversible = false,
                // Not stated by this feed. False means "Red Hat did not say", recorded here rather
                // than presented as a vendor assertion that no reboot is needed.
                RequiresReboot = false,
                Classification = "Security Advisory",
                PublishedAt = released,
                Provenance = provenance,
            });
        }

        // A page with records on it that yields no advisories is a format change, not a quiet day.
        // Without this the feed degrades back to exactly the silent-empty behaviour above.
        if (entries > 0 && advisories.Count == 0)
            throw new InvalidOperationException(
                $"The rhsa feed returned {entries} entries but none carried an 'RHSA' identifier. "
                + "The endpoint's format has changed — refusing to report an empty sync as success.");

        return new NormalizedBatch
        {
            Advisories = advisories,
            Patches = patches,
            Cursor = maxReleased?.ToString("O"),
        };
    }

    /// <summary>
    /// Turns <c>released_packages</c> into fix statements. Each entry is a NEVRA —
    /// <c>name-epoch:version-release.arch</c>, e.g.
    /// <c>ansible-core-1:2.14.18-3.el9_8.1.x86_64</c>.
    ///
    /// <para>Two real shapes are skipped rather than coerced. A <c>.src</c> rpm is not installable,
    /// so it states no applicability fact. And some advisories list module streams
    /// (<c>java-21-openjdk-portable-main@aarch64</c>) which carry no version at all — a fix
    /// statement without a fixed version is not a fix statement.</para>
    ///
    /// <para>Rows are deduplicated because arch is not part of a fix statement: one package at one
    /// version on four arches is ONE row. <c>advisory_affects</c> is unique on
    /// (advisory, package, ecosystem, platform), so emitting four would have the store silently
    /// collapse them anyway — and the reported count would then describe nothing real.</para>
    /// </summary>
    private static IEnumerable<NormalizedAffect> ReadAffects(JsonElement adv)
    {
        var seen = new HashSet<(string Package, string? Platform, string Version)>();

        foreach (var element in adv.Array("released_packages"))
        {
            if (element.GetString() is not { } nevra)
                continue;

            // The epoch colon is the anchor: everything left of it is name-epoch, everything right
            // is version-release.arch. No colon means this is not a versioned package reference.
            var colon = nevra.IndexOf(':');
            if (colon <= 0)
                continue;

            var nameEpoch = nevra[..colon];
            var versionArch = nevra[(colon + 1)..];

            var lastDash = nameEpoch.LastIndexOf('-');
            var lastDot = versionArch.LastIndexOf('.');
            if (lastDash <= 0 || lastDot <= 0)
                continue;

            var name = nameEpoch[..lastDash];
            var epoch = nameEpoch[(lastDash + 1)..];
            var arch = versionArch[(lastDot + 1)..];

            if (string.Equals(arch, "src", StringComparison.OrdinalIgnoreCase))
                continue;

            // RAW as sourced (ADR 0011) — epoch included, because epoch dominates rpmvercmp.
            var fixedVersion = $"{epoch}:{versionArch[..lastDot]}";
            var platform = PlatformFromDistTag(versionArch);

            if (seen.Add((name, platform, fixedVersion)))
                yield return new NormalizedAffect(
                    PackageName: name,
                    Ecosystem: Ecosystems.Rpm,
                    Platform: platform,
                    FixedVersion: fixedVersion,
                    Backported: true);
        }
    }

    /// <summary>
    /// <c>.el9_8</c> / <c>.el10_2</c> → <c>rhel:9</c> / <c>rhel:10</c>. Only the MAJOR is taken: the
    /// minor is the point release the fix shipped in, not a separate platform, and Phase 6 matches
    /// hosts on the major. Null when the dist tag is absent, which is honest — an unlabelled row is
    /// better than one attributed to the wrong release.
    /// </summary>
    private static string? PlatformFromDistTag(string versionArch)
    {
        var match = Regex.Match(versionArch, @"\.el(\d+)", RegexOptions.None, TimeSpan.FromSeconds(1));
        return match.Success ? $"rhel:{match.Groups[1].Value}" : null;
    }

    // Red Hat's four-level severity → our five-band enum. Moderate maps to medium, Important to high.
    private static string MapSeverity(string? raw) => raw?.ToLowerInvariant() switch
    {
        "critical" => "critical",
        "important" => "high",
        "moderate" => "medium",
        "low" => "low",
        _ => "unknown",
    };
}
