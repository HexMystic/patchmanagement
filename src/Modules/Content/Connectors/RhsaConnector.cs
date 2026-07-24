using System.Text.Json;
using PatchManagement.Content.Abstractions;
using PatchManagement.Content.Model;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// Red Hat Security Advisory connector. An RHSA is an advisory + its rpm applicability source: it
/// states the exact fixed NEVR per RHEL product, which is what HARD-PROBLEMS #2 requires (RHEL
/// backports fixes into the same upstream version with a new release, so <c>backported = true</c>).
/// Produces a <see cref="NormalizedAdvisory"/> (source = <c>rhsa</c>) with rpm fix statements and a
/// <see cref="NormalizedPatch"/> (source = <c>rhsa</c>).
///
/// RHSA also serves Rocky/Alma, which rebuild RHEL content (phase-1 Group B): those hosts are
/// assessed against <c>rhsa</c> until native RLSA/ALSA precision is ever needed (a deferred,
/// additive Phase-5/6 decision — never a change to the frozen vocabulary).
///
/// The NEVR (e.g. <c>0:3.0.7-27.el9_3</c>) is carried RAW; the RPM comparator (Phase 6) owns epoch
/// and <c>rpmvercmp</c> semantics (ADR 0011, HARD-PROBLEMS #3).
/// </summary>
public sealed class RhsaConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint =
        "https://access.redhat.com/hydra/rest/securitydata/csaf.json";

    public string Kind => Feeds.Rhsa;

    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        var uri = new Uri(state.Endpoint ?? DefaultEndpoint);
        var json = await fetcher.GetStringAsync(uri, ct);
        return Parse(json, DateTimeOffset.UtcNow);
    }

    public static NormalizedBatch Parse(string json, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var advisories = new List<NormalizedAdvisory>();
        var patches = new List<NormalizedPatch>();
        DateTimeOffset? maxReleased = null;

        foreach (var adv in root.Array("advisories"))
        {
            var id = adv.StringOrNull("id");
            if (string.IsNullOrEmpty(id))
                continue;

            var released = adv.DateTimeOffsetOrNull("released");
            if (released is { } r && (maxReleased is null || r > maxReleased))
                maxReleased = r;

            var cvss = adv.Prop("cvss3");
            var cves = adv.Array("cves").Select(c => c.GetString()).Where(c => c is not null).ToArray();

            var provenance = new[]
            {
                new ProvenanceEntry(
                    Feeds.Rhsa, retrievedAt, SourceRecordId: id,
                    Url: $"https://access.redhat.com/errata/{id}"),
            };

            advisories.Add(new NormalizedAdvisory
            {
                Source = Feeds.Rhsa,
                ExternalId = id,
                Title = adv.StringOrNull("title") ?? id,
                Severity = MapSeverity(adv.StringOrNull("severity")),
                PublishedAt = released,
                CvssBaseScore = cvss?.DoubleOrNull("base_score"),
                CvssVector = cvss?.StringOrNull("vector"),
                CvssVersion = cvss?.StringOrNull("version") ?? (cvss is null ? null : "3.1"),
                CvssSource = cvss is null ? null : Feeds.Rhsa,
                SourceMetadataJson = cves.Length > 0 ? JsonSerializer.Serialize(new { cves }) : null,
                Provenance = provenance,
                Affects = ReadAffects(adv).ToList(),
            });

            patches.Add(new NormalizedPatch
            {
                Source = Feeds.Rhsa,
                VendorId = id,
                Title = adv.StringOrNull("title") ?? id,
                Reversible = false,
                RequiresReboot = adv.BoolOrNull("reboot_required") ?? false,
                Classification = adv.StringOrNull("classification") ?? "Security Advisory",
                PublishedAt = released,
                Provenance = provenance,
            });
        }

        return new NormalizedBatch
        {
            Advisories = advisories,
            Patches = patches,
            Cursor = maxReleased?.ToString("O"),
        };
    }

    private static IEnumerable<NormalizedAffect> ReadAffects(JsonElement adv)
    {
        foreach (var a in adv.Array("affected"))
        {
            var package = a.StringOrNull("package");
            if (string.IsNullOrEmpty(package))
                continue;

            yield return new NormalizedAffect(
                PackageName: package,
                Ecosystem: Ecosystems.Rpm,
                Platform: a.StringOrNull("product"),
                FixedVersion: a.StringOrNull("fixed_version"),
                Backported: true);
        }
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
