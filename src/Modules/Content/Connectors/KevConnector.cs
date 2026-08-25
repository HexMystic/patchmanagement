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

    /// <summary>
    /// CISA serves one whole file with no filter parameter, so the cursor reaches the feed as HTTP
    /// validators. A 304 is the server ASSERTING that nothing changed — the opposite of the
    /// empty-parse hazard this module throws on, which infers absence from silence.
    /// </summary>
    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        var uri = new Uri(state.Endpoint ?? DefaultEndpoint);
        var cursor = FeedCursor.Read(state.Cursor);

        var fetch = await fetcher.GetStringConditionalAsync(uri, cursor.ETag, cursor.LastModified, ct);

        // Hand the stored value straight back, validators and all. Re-formatting it would work;
        // returning state.Cursor verbatim makes it impossible for this path to lose a validator.
        if (fetch.NotModified)
            return new NormalizedBatch { Cursor = state.Cursor };

        var batch = Parse(fetch.Content!, DateTimeOffset.UtcNow);
        return batch with { Cursor = FeedCursor.From(batch.Cursor, fetch).Format() };
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
                KnownRansomwareUse: RansomwareUse(v.StringOrNull("knownRansomwareCampaignUse")),
                Provenance: new ProvenanceEntry(Feeds.Kev, retrievedAt, SourceRecordId: cve, Url: CatalogUrl)));
        }

        // The catalogue version is the semantic half of the cursor. The half that reaches CISA is
        // the HTTP validators SyncAsync pairs with it — this file offers no filter parameter.
        var cursor = root.StringOrNull("catalogVersion") ?? root.StringOrNull("dateReleased");

        return new NormalizedBatch { KevOverlays = overlays, Cursor = cursor };
    }

    /// <summary>
    /// Only a confirmed "Known" becomes <c>true</c>. CISA's literal "Unknown" means <em>not
    /// confirmed</em>, not <em>confirmed absent</em>, so it maps to null alongside absence and any
    /// unrecognised value — we never assert "no ransomware" on the strength of the source not
    /// saying so.
    ///
    /// <para>This mapping returned <c>false</c> for "Unknown" until it was tested, contradicting the
    /// comment that sat directly above it. Recording false lets Phase 7 read an absence of evidence
    /// as evidence of absence — the same mistake the frozen schema already forbids for the sibling
    /// field, where <c>kev.listed</c>'s description warns that collapsing "not evaluated" into false
    /// "would let Phase 7 weight a never-run sync identically to a confirmed absence".</para>
    /// </summary>
    private static bool? RansomwareUse(string? raw) => raw?.ToLowerInvariant() switch
    {
        "known" => true,
        _ => null,
    };
}
