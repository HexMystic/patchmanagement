using System.Globalization;
using System.Text.Json;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// FIRST EPSS connector. Like KEV, EPSS is a scoring OVERLAY: it supplies an exploit-probability for
/// a CVE. It emits <see cref="EpssOverlay"/> records that set <c>epss_*</c> on the matching advisory
/// and append an <c>epss</c> provenance entry, never inserting an advisory.
///
/// The API returns <c>epss</c> and <c>percentile</c> as decimal strings in [0,1] — probabilities,
/// not percentages. They are carried through unscaled; the DB CHECK rejects anything &gt; 1, so a
/// stray ×100 fails loudly instead of silently inflating Phase 7 risk.
/// </summary>
public sealed class EpssConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint = "https://api.first.org/data/v1/epss";
    private const string ApiUrl = "https://api.first.org/data/v1/epss";

    public string Kind => Feeds.Epss;

    /// <summary>
    /// EPSS republishes EVERY score daily and the cursor is the model date. FIRST offers no "has the
    /// model moved?" question and no validator worth storing, so the fetch always happens and the
    /// cursor bounds what is WRITTEN: an unmoved model date means the overlays already applied are
    /// the current ones, and re-applying ~250,000 of them is pure no-op churn per run.
    ///
    /// <para>Stated plainly because it is the weakest incrementality of the eight: it saves database
    /// work, not bandwidth. The alternative — inventing a filter parameter FIRST does not serve —
    /// is the defect this module keeps deleting.</para>
    /// </summary>
    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        var uri = new Uri(state.Endpoint ?? DefaultEndpoint);
        var json = await fetcher.GetStringAsync(uri, ct);
        var batch = Parse(json, DateTimeOffset.UtcNow);

        var since = FeedCursor.Read(state.Cursor).Semantic;

        return batch.Cursor is not null && batch.Cursor == since
            ? new NormalizedBatch { Cursor = state.Cursor }
            : batch;
    }

    public static NormalizedBatch Parse(string json, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var overlays = new List<EpssOverlay>();
        string? modelDate = null;

        foreach (var d in root.Array("data"))
        {
            var cve = d.StringOrNull("cve");
            var score = d.DoubleOrNull("epss");
            if (string.IsNullOrEmpty(cve) || score is null)
                continue;

            modelDate ??= d.StringOrNull("date");

            overlays.Add(new EpssOverlay(
                CveId: cve,
                Score: score.Value,
                Percentile: d.DoubleOrNull("percentile"),
                ScoredAt: ParseModelDate(d.StringOrNull("date")),
                Provenance: new ProvenanceEntry(Feeds.Epss, retrievedAt, SourceRecordId: cve, Url: ApiUrl)));
        }

        // The EPSS model date is the incremental bookmark — scores are re-published daily.
        return new NormalizedBatch { EpssOverlays = overlays, Cursor = modelDate };
    }

    private static DateTimeOffset? ParseModelDate(string? date) =>
        DateOnly.TryParse(date, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
            ? new DateTimeOffset(d.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero)
            : null;
}
