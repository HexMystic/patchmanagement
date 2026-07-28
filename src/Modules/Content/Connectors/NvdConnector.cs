using System.Text.Json;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// NVD API 2.0 connector. NVD is the CVE OVERLAY, not an applicability engine (ADR 0008/0011):
/// it supplies severity + CVSS for a CVE. It therefore produces <see cref="NormalizedAdvisory"/>
/// records (source = <c>nvd</c>) with NO <c>advisory_affects</c> rows — NVD publishes affected
/// version RANGES, which HARD-PROBLEMS #2 rejects as an applicability basis (blind to backports)
/// and ADR 0011 keeps out of that table. Distro advisories (USN/RHSA/DSA) own the fix statements.
///
/// Idempotent: a re-run upserts the same rows.
///
/// <para><b>NOT incremental, despite emitting a cursor.</b> <c>Parse</c> computes the latest
/// <c>lastModified</c> and <c>ContentSyncService</c> persists it, but <c>SyncAsync</c> never reads
/// <c>state.Cursor</c> and never appends <c>lastModStartDate</c> to the request — so every run
/// re-fetches the same window. This doc previously claimed the opposite. <b>Pagination is ignored
/// too</b>: <c>startIndex</c>/<c>totalResults</c>/<c>resultsPerPage</c> are never read, so a
/// response spanning more than one page is silently truncated to the first. Both are recorded in
/// <c>docs/phases/phase-5.md</c>.</para>
/// </summary>
public sealed class NvdConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /// <summary>The <c>source</c> identifier NVD stamps on scores it computed itself.</summary>
    private const string NvdScoreSource = "nvd@nist.gov";

    public string Kind => Feeds.Nvd;

    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        var uri = new Uri(state.Endpoint ?? DefaultEndpoint);
        var json = await fetcher.GetStringAsync(uri, ct);
        return Parse(json, DateTimeOffset.UtcNow);
    }

    /// <summary>Pure parse — exposed so tests can drive it without the fetcher.</summary>
    public static NormalizedBatch Parse(string json, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var advisories = new List<NormalizedAdvisory>();
        DateTimeOffset? maxModified = null;

        foreach (var item in root.Array("vulnerabilities"))
        {
            if (item.Prop("cve") is not { } cve)
                continue;

            var id = cve.StringOrNull("id");
            if (string.IsNullOrEmpty(id))
                continue;

            var modified = cve.DateTimeOffsetOrNull("lastModified");
            if (modified is { } m && (maxModified is null || m > maxModified))
                maxModified = m;

            var cvss = ReadCvss(cve);

            advisories.Add(new NormalizedAdvisory
            {
                Source = Feeds.Nvd,
                ExternalId = id,
                Title = FirstEnglishDescription(cve) ?? id,
                Severity = cvss.Severity,
                PublishedAt = cve.DateTimeOffsetOrNull("published"),
                CvssBaseScore = cvss.Score,
                CvssVector = cvss.Vector,
                CvssVersion = cvss.Version,
                // Only when NVD authored the chosen metric. A vendor's score is kept above but left
                // unattributed rather than mislabelled — see ReadCvss.
                CvssSource = cvss.Score is not null && cvss.FromNvd ? Feeds.Nvd : null,
                SourceMetadataJson = OriginatorMetadata(cvss),
                Provenance =
                [
                    new ProvenanceEntry(
                        Feeds.Nvd, retrievedAt, SourceRecordId: id,
                        Url: $"https://nvd.nist.gov/vuln/detail/{id}"),
                ],
            });
        }

        return new NormalizedBatch
        {
            Advisories = advisories,
            Cursor = maxModified?.ToString("O"),
        };
    }

    /// <summary>
    /// Records who published a score we could not attribute to one of our own feeds, so nulling
    /// <c>CvssSource</c> hides the mislabelling without also losing the answer. Serialized rather
    /// than interpolated so an exotic CNA identifier cannot produce malformed JSON.
    /// </summary>
    private static string? OriginatorMetadata(CvssReading cvss) =>
        cvss.Score is not null && cvss.Originator is { Length: > 0 } originator
            ? JsonSerializer.Serialize(new { cvssOriginator = originator })
            : null;

    private static string? FirstEnglishDescription(JsonElement cve)
    {
        foreach (var d in cve.Array("descriptions"))
            if (d.StringOrNull("lang") == "en")
                return d.StringOrNull("value");
        return null;
    }

    /// <summary>
    /// Prefer CVSS v3.1, then v3.0, then v2 — the newest metric family present for this CVE — and
    /// WITHIN a family prefer the score NVD itself published.
    ///
    /// <para>Each family is an ARRAY carrying every scoring party's opinion, and NVD does not
    /// guarantee its own comes first. Taking <c>[0]</c> imports whichever CNA happens to lead: on
    /// CVE-2024-0182 that is vuldb at 7.3/HIGH where NVD says 9.8/CRITICAL — a different severity
    /// band. Across 300 consecutive real CVEs, 125 are shaped that way, so this is the ordinary case
    /// rather than an edge one.</para>
    ///
    /// <para>Attribution follows selection: <c>CvssSource</c> is set to <c>nvd</c> only when the
    /// chosen metric really is NVD's. When a CVE carries only a vendor's score (Qualcomm on
    /// CVE-2023-33025) the score is still worth keeping, but it is left UNATTRIBUTED — the schema
    /// constrains <c>cvss.source</c> to the eight feed names, so the vendor's own identifier cannot
    /// go there, and claiming <c>nvd</c> would be a provenance lie in the one field whose entire job
    /// is to say who scored it (CLAUDE.md §4.6).</para>
    /// </summary>
    private static CvssReading ReadCvss(JsonElement cve)
    {
        if (cve.Prop("metrics") is not { } metrics)
            return CvssReading.None;

        foreach (var key in new[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
        {
            // A family may be present but hold nothing scorable (e.g. an entry with no cvssData),
            // in which case fall through to the next family rather than giving up entirely.
            if (SelectMetric(metrics.Array(key)) is not { } metric)
                continue;

            if (metric.Prop("cvssData") is not { } data)
                continue;

            var score = data.DoubleOrNull("baseScore");
            var vector = data.StringOrNull("vectorString");
            var version = data.StringOrNull("version");
            // v3 carries baseSeverity inline; v2 carries it on the metric wrapper.
            var severity = NormalizeSeverity(data.StringOrNull("baseSeverity")
                ?? metric.StringOrNull("baseSeverity")
                ?? SeverityFromScore(score));

            var fromNvd = IsNvdAuthored(metric);

            return new CvssReading(
                score, vector, version, severity, fromNvd,
                // Only when we could NOT attribute it to a feed — otherwise CvssSource already
                // carries the answer and this would be noise on every record in the corpus.
                Originator: fromNvd ? null : metric.StringOrNull("source"));
        }

        return CvssReading.None;
    }

    /// <summary>
    /// One CVSS metric, read. <see cref="Originator"/> is the scoring party's own identifier
    /// (an email or CNA UUID) and is set only when the score is NOT NVD's, because
    /// <c>advisories.cvss_source</c> is CHECK-constrained to the eight feed names and cannot hold
    /// it. Preserved in <c>source_metadata</c> so "who scored this?" stays answerable.
    /// </summary>
    private readonly record struct CvssReading(
        double? Score,
        string? Vector,
        string? Version,
        string Severity,
        bool FromNvd,
        string? Originator)
    {
        public static CvssReading None { get; } = new(null, null, null, "unknown", false, null);
    }

    /// <summary>
    /// NVD's own metric if it published one, else the designated Primary, else the first scorable
    /// entry. Ordering within the array is deliberately NOT used as a tie-break — it is exactly the
    /// signal that proved unreliable.
    /// </summary>
    private static JsonElement? SelectMetric(IEnumerable<JsonElement> family)
    {
        JsonElement? primary = null;
        JsonElement? first = null;

        foreach (var metric in family)
        {
            if (metric.Prop("cvssData") is null)
                continue;

            if (IsNvdAuthored(metric))
                return metric;

            if (primary is null && metric.StringOrNull("type") == "Primary")
                primary = metric;

            first ??= metric;
        }

        return primary ?? first;
    }

    /// <summary>
    /// Authorship is the <c>source</c> identifier, not the <c>type</c> flag: NVD marks a metric
    /// Primary when it adopts a CNA's analysis as authoritative, which is a statement about status,
    /// not about who computed the score.
    /// </summary>
    private static bool IsNvdAuthored(JsonElement metric) =>
        metric.StringOrNull("source") == NvdScoreSource;

    private static string NormalizeSeverity(string? raw) => raw?.ToLowerInvariant() switch
    {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "none" => "none",
        _ => "unknown",
    };

    // CVSS v2 has no CRITICAL band; used only as a last resort when the feed states no severity.
    private static string? SeverityFromScore(double? score) => score switch
    {
        null => null,
        >= 9.0 => "critical",
        >= 7.0 => "high",
        >= 4.0 => "medium",
        > 0.0 => "low",
        _ => "none",
    };
}
