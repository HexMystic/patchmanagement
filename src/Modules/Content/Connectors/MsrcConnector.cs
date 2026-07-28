using System.Text.Json;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// Microsoft Security Response Center (CSAF) connector — the Windows ADVISORY side of ADR 0008
/// (wsusscn2.cab is the applicability/patch side). MSRC answers "which CVEs a KB fixes, and how
/// severe": it produces <see cref="NormalizedAdvisory"/> records keyed on the CVE (source =
/// <c>msrc</c>) plus <see cref="NormalizedPatch"/> records keyed on the KB (source = <c>msrc</c>).
///
/// One KB routinely fixes several CVEs, so patches are DEDUPED by KB across the whole document and
/// their supersedence lists merged — otherwise the same KB would be upserted repeatedly and its
/// edges double-counted. Windows fix statements carry the product/component as <c>package_name</c>
/// and the fixed BUILD as <c>fixed_version</c>, raw (ADR 0011 known-limit for windows rows).
/// </summary>
public sealed class MsrcConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint = "https://api.msrc.microsoft.com/cvrf/v3.0/csaf";

    public string Kind => Feeds.Msrc;

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
        var patchesByKb = new Dictionary<string, PatchAccumulator>(StringComparer.OrdinalIgnoreCase);
        DateTimeOffset? maxReleased = null;

        foreach (var vuln in root.Array("vulnerabilities"))
        {
            var cve = vuln.StringOrNull("cve");
            if (string.IsNullOrEmpty(cve))
                continue;

            var released = vuln.DateTimeOffsetOrNull("released");
            if (released is { } r && (maxReleased is null || r > maxReleased))
                maxReleased = r;

            var cvss = vuln.Prop("cvss");
            var provenance = new[]
            {
                new ProvenanceEntry(
                    Feeds.Msrc, retrievedAt, SourceRecordId: cve,
                    Url: $"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"),
            };

            var affects = new List<NormalizedAffect>();
            var kbs = new List<string>();

            foreach (var rem in vuln.Array("remediations"))
            {
                var kb = rem.StringOrNull("kb");
                var product = rem.StringOrNull("product");
                var platform = rem.StringOrNull("platform") ?? product;
                var fixedBuild = rem.StringOrNull("fixed_build");

                if (!string.IsNullOrEmpty(product))
                    affects.Add(new NormalizedAffect(
                        PackageName: product,
                        Ecosystem: Ecosystems.Windows,
                        Platform: platform,
                        FixedVersion: fixedBuild,
                        Backported: false));

                if (string.IsNullOrEmpty(kb))
                    continue;

                var vendorId = NormalizeKb(kb);
                kbs.Add(vendorId);

                if (!patchesByKb.TryGetValue(vendorId, out var acc))
                    patchesByKb[vendorId] = acc = new PatchAccumulator(vendorId, product, released, retrievedAt);

                acc.Title ??= product;
                acc.RequiresReboot |= rem.BoolOrNull("reboot") ?? false;
                foreach (var s in rem.Array("supersedes"))
                    if (s.GetString() is { } sup)
                        acc.Supersedes.Add(NormalizeKb(sup));
            }

            advisories.Add(new NormalizedAdvisory
            {
                Source = Feeds.Msrc,
                ExternalId = cve,
                Title = vuln.StringOrNull("title") ?? cve,
                Severity = MapSeverity(vuln.StringOrNull("severity")),
                PublishedAt = released,
                CvssBaseScore = cvss?.DoubleOrNull("base_score"),
                CvssVector = cvss?.StringOrNull("vector"),
                CvssVersion = cvss?.StringOrNull("version") ?? (cvss is null ? null : "3.1"),
                CvssSource = cvss is null ? null : Feeds.Msrc,
                SourceMetadataJson = kbs.Count > 0
                    ? JsonSerializer.Serialize(new { kbs = kbs.Distinct().ToArray() })
                    : null,
                Provenance = provenance,
                Affects = affects,
            });
        }

        var patches = patchesByKb.Values.Select(a => a.Build()).ToList();

        return new NormalizedBatch
        {
            Advisories = advisories,
            Patches = patches,
            Cursor = root.StringOrNull("id") ?? maxReleased?.ToString("O"),
        };
    }

    private static string NormalizeKb(string kb) =>
        kb.StartsWith("KB", StringComparison.OrdinalIgnoreCase) ? kb.ToUpperInvariant() : $"KB{kb}";

    private static string MapSeverity(string? raw) => raw?.ToLowerInvariant() switch
    {
        "critical" => "critical",
        "important" => "high",
        "moderate" => "medium",
        "low" => "low",
        _ => "unknown",
    };

    private sealed class PatchAccumulator(string vendorId, string? title, DateTimeOffset? released, DateTimeOffset retrievedAt)
    {
        public string? Title { get; set; } = title;
        public bool RequiresReboot { get; set; }
        public HashSet<string> Supersedes { get; } = new(StringComparer.OrdinalIgnoreCase);

        public NormalizedPatch Build() => new()
        {
            Source = Feeds.Msrc,
            VendorId = vendorId,
            Title = Title ?? vendorId,
            Reversible = false,
            RequiresReboot = RequiresReboot,
            Classification = "Security Updates",
            PublishedAt = released,
            Provenance = [new ProvenanceEntry(Feeds.Msrc, retrievedAt, SourceRecordId: vendorId)],
            Supersedes = Supersedes.ToList(),
        };
    }
}
