using System.Globalization;
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
/// <para><b>Incremental via <c>lastModStartDate</c> — and this time the request carries it.</b> The
/// cursor is the newest <c>lastModified</c> seen, and it goes back out as the start of the window.
/// NVD rejects that parameter unless <c>lastModEndDate</c> accompanies it, so both are always sent
/// together or neither is. A doc comment here once made this claim while <c>SyncAsync</c> sent
/// nothing; <c>IncrementalSyncTests</c> is what makes it true rather than asserted.</para>
///
/// <para><b>Pagination is followed.</b> <c>startIndex</c>/<c>resultsPerPage</c>/<c>totalResults</c>
/// were read by nothing, so a response spanning more than one page was truncated to the first and
/// reported <c>ok</c>. The loop below walks to the last page and is bounded by
/// <see cref="MaxPages"/> — a malformed counter must stop the sync loudly rather than spin.</para>
///
/// <para><b>A cursor older than NVD's 120-day window limit falls back to a full fetch</b>, which is
/// expensive and correct, rather than being clamped forward, which is cheap and silently lossy. A
/// feed this stale is a recovery case; walking it in 120-day chunks is the obvious refinement and is
/// named as a gap in <c>docs/phases/phase-5.md</c> rather than half-built here.</para>
/// </summary>
public sealed class NvdConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /// <summary>The <c>source</c> identifier NVD stamps on scores it computed itself.</summary>
    private const string NvdScoreSource = "nvd@nist.gov";

    public string Kind => Feeds.Nvd;

    /// <summary>NVD's documented ceiling on a single <c>lastMod</c> window.</summary>
    private static readonly TimeSpan MaxWindow = TimeSpan.FromDays(120);

    /// <summary>
    /// Enough for a full catalogue at NVD's 2,000-per-page maximum, with headroom. Exceeding it
    /// means the counters are not describing a real result set, which must fail loudly.
    /// </summary>
    private const int MaxPages = 1_000;

    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        var baseUri = new Uri(state.Endpoint ?? DefaultEndpoint);
        var retrievedAt = DateTimeOffset.UtcNow;
        var window = WindowFrom(FeedCursor.Read(state.Cursor).Semantic, retrievedAt);

        var advisories = new List<NormalizedAdvisory>();
        string? newest = null;
        int? startIndex = 0;

        for (var page = 0; startIndex is { } offset; page++)
        {
            ct.ThrowIfCancellationRequested();

            if (page >= MaxPages)
                throw new InvalidOperationException(
                    $"The nvd feed reported more than {MaxPages} pages. Its paging counters are not "
                    + "describing a real result set — refusing to keep requesting indefinitely.");

            var json = await fetcher.GetStringAsync(
                FeedUri.With(
                    baseUri,
                    ("lastModStartDate", window.Start),
                    ("lastModEndDate", window.End),
                    ("startIndex", offset == 0 ? null : offset.ToString(CultureInfo.InvariantCulture))),
                ct);

            var batch = Parse(json, retrievedAt);
            advisories.AddRange(batch.Advisories);
            newest = Later(newest, batch.Cursor);
            startIndex = ReadPaging(json).NextStartIndex;
        }

        return new NormalizedBatch
        {
            Advisories = advisories,
            // Hold the old cursor when a window returned nothing: null would re-open the whole
            // catalogue on the next run, turning one quiet sync into a full re-ingest.
            Cursor = newest ?? state.Cursor,
        };
    }

    /// <summary>
    /// The window to request. Both bounds or neither: NVD 404s a lone <c>lastModStartDate</c>, so a
    /// half-built window would fail every incremental run after release rather than at review time.
    /// </summary>
    private static (string? Start, string? End) WindowFrom(string? cursor, DateTimeOffset now)
    {
        if (!DateTimeOffset.TryParse(
                cursor, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var since))
            return (null, null);

        // Older than the ceiling: ask for everything rather than silently starting the window
        // 120 days ago and skipping the gap in between.
        if (now - since > MaxWindow)
            return (null, null);

        return (NvdInstant(since), NvdInstant(now));
    }

    /// <summary>NVD's ISO-8601 form: millisecond precision, explicit UTC.</summary>
    private static string NvdInstant(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

    /// <summary>Keeps the later of two cursors while pages are merged.</summary>
    private static string? Later(string? a, string? b)
    {
        if (a is null)
            return b;
        if (b is null)
            return a;

        return string.CompareOrdinal(a, b) >= 0 ? a : b;
    }

    /// <summary>
    /// Reads the paging counters. Exposed as its own step because <see cref="Parse"/> is the pure
    /// record transform and must stay callable on a single page with no notion of the run around it.
    /// </summary>
    public static NvdPaging ReadPaging(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        return new NvdPaging(
            IntOr(root, "startIndex", 0),
            IntOr(root, "resultsPerPage", 0),
            IntOr(root, "totalResults", 0));
    }

    private static int IntOr(JsonElement e, string name, int fallback) =>
        e.ValueKind == JsonValueKind.Object
        && e.TryGetProperty(name, out var v)
        && v.ValueKind == JsonValueKind.Number
        && v.TryGetInt32(out var i)
            ? i
            : fallback;

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
