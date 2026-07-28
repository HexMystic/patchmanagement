using System.Globalization;
using System.Text.Json;
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
/// Fixes are <c>backported = true</c> (Debian's <c>~debNuM</c> suffix is a backport into the frozen
/// upstream version). The version is carried RAW; only the suite codename is mapped to
/// <c>debian:NN</c> (ADR 0011).
/// </summary>
public sealed class DebianDsaConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint = "https://security-tracker.debian.org/tracker/data/dsa.json";

    public string Kind => Feeds.Dsa;

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
        double maxTimestamp = 0;

        foreach (var entry in root.EnumerateObject())
        {
            var dsa = entry.Value;
            var externalId = dsa.StringOrNull("id") ?? entry.Name;
            var title = dsa.StringOrNull("title") ?? externalId;

            var ts = dsa.DoubleOrNull("timestamp");
            if (ts is { } t && t > maxTimestamp)
                maxTimestamp = t;

            var affects = ReadAffects(dsa).ToList();
            var cves = dsa.Array("cves").Select(c => c.GetString()).Where(c => c is not null).ToArray();

            var provenance = new[]
            {
                new ProvenanceEntry(
                    Feeds.Dsa, retrievedAt, SourceRecordId: externalId,
                    Url: $"https://security-tracker.debian.org/tracker/{externalId}"),
            };

            advisories.Add(new NormalizedAdvisory
            {
                Source = Feeds.Dsa,
                ExternalId = externalId,
                Title = title,
                Severity = "unknown",
                PublishedAt = FromUnix(ts),
                SourceMetadataJson = cves.Length > 0 ? JsonSerializer.Serialize(new { cves }) : null,
                Provenance = provenance,
                Affects = affects,
            });

            patches.Add(new NormalizedPatch
            {
                Source = Feeds.Dsa,
                VendorId = externalId,
                Title = title,
                Reversible = false,
                RequiresReboot = false,
                Classification = "Security Updates",
                PublishedAt = FromUnix(ts),
                Provenance = provenance,
            });
        }

        return new NormalizedBatch
        {
            Advisories = advisories,
            Patches = patches,
            Cursor = maxTimestamp > 0 ? maxTimestamp.ToString("R", CultureInfo.InvariantCulture) : null,
        };
    }

    private static IEnumerable<NormalizedAffect> ReadAffects(JsonElement dsa)
    {
        if (dsa.Prop("releases") is not { ValueKind: JsonValueKind.Object } releases)
            yield break;

        foreach (var release in releases.EnumerateObject())
        {
            var platform = DistroReleases.DebianPlatform(release.Name);
            // Debian feeds use "packages"; tolerate "sources" too for USN-shaped mirrors.
            var packages = release.Value.Prop("packages") ?? release.Value.Prop("sources");
            if (packages is not { ValueKind: JsonValueKind.Object } pkgs)
                continue;

            foreach (var pkg in pkgs.EnumerateObject())
            {
                var version = pkg.Value.StringOrNull("version");
                yield return new NormalizedAffect(
                    PackageName: pkg.Name,
                    Ecosystem: Ecosystems.Deb,
                    Platform: platform,
                    FixedVersion: version,
                    Backported: true);
            }
        }
    }

    private static DateTimeOffset? FromUnix(double? seconds) =>
        seconds is { } s ? DateTimeOffset.FromUnixTimeMilliseconds((long)(s * 1000)) : null;
}
