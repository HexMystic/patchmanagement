using System.Text.Json;
using PatchManagement.Content.Abstractions;
using PatchManagement.Content.Model;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// NVD API 2.0 connector. NVD is the CVE OVERLAY, not an applicability engine (ADR 0008/0011):
/// it supplies severity + CVSS for a CVE. It therefore produces <see cref="NormalizedAdvisory"/>
/// records (source = <c>nvd</c>) with NO <c>advisory_affects</c> rows — NVD publishes affected
/// version RANGES, which HARD-PROBLEMS #2 rejects as an applicability basis (blind to backports)
/// and ADR 0011 keeps out of that table. Distro advisories (USN/RHSA/DSA) own the fix statements.
///
/// Incremental via <c>lastModStartDate</c>: the cursor is the latest <c>lastModified</c> seen, and
/// the next run asks NVD only for records changed since. Idempotent: a re-run upserts the same rows.
/// </summary>
public sealed class NvdConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    public const string DefaultEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0";

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

            var (score, vector, version, severity) = ReadCvss(cve);

            advisories.Add(new NormalizedAdvisory
            {
                Source = Feeds.Nvd,
                ExternalId = id,
                Title = FirstEnglishDescription(cve) ?? id,
                Severity = severity,
                PublishedAt = cve.DateTimeOffsetOrNull("published"),
                CvssBaseScore = score,
                CvssVector = vector,
                CvssVersion = version,
                CvssSource = score is null ? null : Feeds.Nvd,
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

    private static string? FirstEnglishDescription(JsonElement cve)
    {
        foreach (var d in cve.Array("descriptions"))
            if (d.StringOrNull("lang") == "en")
                return d.StringOrNull("value");
        return null;
    }

    // Prefer CVSS v3.1, then v3.0, then v2 — the newest metric NVD supplies for this CVE.
    private static (double? Score, string? Vector, string? Version, string Severity) ReadCvss(JsonElement cve)
    {
        if (cve.Prop("metrics") is not { } metrics)
            return (null, null, null, "unknown");

        foreach (var key in new[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
        {
            foreach (var metric in metrics.Array(key))
            {
                if (metric.Prop("cvssData") is not { } data)
                    continue;

                var score = data.DoubleOrNull("baseScore");
                var vector = data.StringOrNull("vectorString");
                var version = data.StringOrNull("version");
                // v3 carries baseSeverity inline; v2 carries it on the metric wrapper.
                var severity = NormalizeSeverity(data.StringOrNull("baseSeverity")
                    ?? metric.StringOrNull("baseSeverity")
                    ?? SeverityFromScore(score));
                return (score, vector, version, severity);
            }
        }

        return (null, null, null, "unknown");
    }

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
