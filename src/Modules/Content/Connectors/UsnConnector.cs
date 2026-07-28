using System.Globalization;
using System.Text.Json;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// Ubuntu Security Notices connector (the usn-db JSON: a map of USN id → notice). A USN is BOTH an
/// advisory ("why") and the applicability source for its fix ("upgrade to this exact Ubuntu package
/// version") — so it produces a <see cref="NormalizedAdvisory"/> (source = <c>usn</c>) carrying the
/// per-release fix statements AND a <see cref="NormalizedPatch"/> (source = <c>usn</c>).
///
/// Fix statements are marked <c>backported = true</c>: Ubuntu backports security fixes into the
/// distro package version, which is exactly the case that makes naive upstream-version comparison
/// produce mass false positives (HARD-PROBLEMS #2). The fixed version is carried RAW; only the
/// release codename is mapped to the <c>ubuntu:XX.YY</c> platform label the rest of the system uses
/// (ADR 0011 — the version string itself is never touched).
/// </summary>
public sealed class UsnConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint = "https://usn.ubuntu.com/usn-db/database.json";

    public string Kind => Feeds.Usn;

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
            var usn = entry.Value;
            var rawId = usn.StringOrNull("id") ?? entry.Name;
            var externalId = rawId.StartsWith("USN-", StringComparison.OrdinalIgnoreCase) ? rawId : $"USN-{rawId}";
            var title = usn.StringOrNull("title") ?? externalId;

            var ts = usn.DoubleOrNull("timestamp");
            if (ts is { } t && t > maxTimestamp)
                maxTimestamp = t;

            var affects = ReadAffects(usn).ToList();
            var cves = usn.Array("cves").Select(c => c.GetString()).Where(c => c is not null).ToArray();

            var provenance = new[]
            {
                new ProvenanceEntry(
                    Feeds.Usn, retrievedAt, SourceRecordId: rawId,
                    Url: $"https://ubuntu.com/security/notices/{externalId}"),
            };

            advisories.Add(new NormalizedAdvisory
            {
                Source = Feeds.Usn,
                ExternalId = externalId,
                Title = title,
                // USN does not publish a normalized severity band; leave it honest rather than guess.
                Severity = "unknown",
                PublishedAt = FromUnix(ts),
                SourceMetadataJson = cves.Length > 0
                    ? JsonSerializer.Serialize(new { cves })
                    : null,
                Provenance = provenance,
                Affects = affects,
            });

            patches.Add(new NormalizedPatch
            {
                Source = Feeds.Usn,
                VendorId = externalId,
                Title = title,
                // apt can revert a package, but we do not assert rollback safety the vendor never
                // stated; and Ubuntu does not flag reboot per-notice, so both default false (safe).
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

    private static IEnumerable<NormalizedAffect> ReadAffects(JsonElement usn)
    {
        if (usn.Prop("releases") is not { ValueKind: JsonValueKind.Object } releases)
            yield break;

        foreach (var release in releases.EnumerateObject())
        {
            var platform = DistroReleases.UbuntuPlatform(release.Name);
            if (release.Value.Prop("sources") is not { ValueKind: JsonValueKind.Object } sources)
                continue;

            foreach (var source in sources.EnumerateObject())
            {
                var version = source.Value.StringOrNull("version");
                yield return new NormalizedAffect(
                    PackageName: source.Name,
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
