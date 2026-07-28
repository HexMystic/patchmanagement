using System.Text.Json;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// CISA KEV connector. KEV is a scoring OVERLAY, not a publisher (schema forbids
/// <c>source = 'kev'</c>): it asserts a CVE is known-exploited. It therefore emits
/// <see cref="KevOverlay"/> records that enrich the matching advisory's <c>kev_*</c> columns and
/// append a <c>kev</c> provenance entry — it never inserts an advisory. If no advisory carries the
/// CVE yet, the overlay enriches zero rows (honest no-op) and takes effect once NVD/vendor ingest
/// creates it.
/// </summary>
public sealed class KevConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private const string CatalogUrl = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";

    public string Kind => Feeds.Kev;

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

        var overlays = new List<KevOverlay>();
        foreach (var v in root.Array("vulnerabilities"))
        {
            var cve = v.StringOrNull("cveID");
            if (string.IsNullOrEmpty(cve))
                continue;

            overlays.Add(new KevOverlay(
                CveId: cve,
                DateAdded: v.DateOnlyOrNull("dateAdded"),
                DueDate: v.DateOnlyOrNull("dueDate"),
                // The feed spells this "Known" / "Unknown"; anything not clearly "Known" is null,
                // not false — we do not assert "no ransomware" when the source is silent.
                KnownRansomwareUse: RansomwareUse(v.StringOrNull("knownRansomwareCampaignUse")),
                Provenance: new ProvenanceEntry(Feeds.Kev, retrievedAt, SourceRecordId: cve, Url: CatalogUrl)));
        }

        // The catalog version is a natural incremental bookmark, though KEV is small enough to
        // re-scan fully; carry it so a future delta fetch has something to compare.
        var cursor = root.StringOrNull("catalogVersion") ?? root.StringOrNull("dateReleased");

        return new NormalizedBatch { KevOverlays = overlays, Cursor = cursor };
    }

    private static bool? RansomwareUse(string? raw) => raw?.ToLowerInvariant() switch
    {
        "known" => true,
        "unknown" => false,
        _ => null,
    };
}
