using System.Text.Json;
using System.Text.RegularExpressions;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// Microsoft Security Response Center connector — the Windows ADVISORY side of ADR 0008
/// (wsusscn2.cab is the applicability/patch side). MSRC answers "which CVEs a KB fixes, and how
/// severe": it produces <see cref="NormalizedAdvisory"/> records keyed on the CVE (source =
/// <c>msrc</c>) plus <see cref="NormalizedPatch"/> records keyed on the KB (source = <c>msrc</c>).
///
/// <para><b>Rewritten 2026-08-21 against a real captured payload.</b> The previous endpoint,
/// <c>cvrf/v3.0/csaf</c>, returns <b>400</b>, and the parser expected an invented
/// <c>root.vulnerabilities[].remediations[].kb</c> envelope. Microsoft serves CVRF in two calls: a
/// monthly index at <c>cvrf/v3.0/updates</c>, then one document per month.</para>
///
/// <para><b>The remediation types are not what the CVRF spec's numbering implies</b> — this was
/// measured, not assumed, and getting it wrong is precisely how a parser ends up returning an empty
/// batch that the sync reports as <c>ok</c>:</para>
/// <list type="bullet">
///   <item><b>Type 2</b> is the vendor fix: the KB in <c>Description.Value</c>, plus
///     <c>FixedBuild</c>, <c>RestartRequired</c> and <c>Supercedence</c>.</item>
///   <item><b>Type 3</b> carries no <c>Description</c> at all — a mitigation URL.</item>
///   <item><b>Type 6</b> is a KB article reference, duplicating a KB already on Type 2.</item>
/// </list>
///
/// <para>And Type 2's description is only <em>sometimes</em> a KB: for non-Windows products
/// (Visual Studio Code, Teams, Azure Linux) it is a label such as <c>"Release Notes"</c>. Trusting
/// it blindly would mint a patch whose <c>vendor_id</c> is that label and then dedupe every such
/// product onto it, so it is accepted only when it looks like a KB number.</para>
///
/// One KB routinely fixes several CVEs, so patches are DEDUPED by KB across the whole document and
/// their supersedence lists merged. Windows fix statements carry the product as
/// <c>package_name</c> and the fixed BUILD as <c>fixed_version</c>, raw (ADR 0011).
/// </summary>
public sealed class MsrcConnector(IHttpContentFetcher fetcher) : IContentConnector
{
    /// <summary>The monthly INDEX. The document for a month is a second call (see <see cref="MsrcMonth"/>).</summary>
    public const string DefaultEndpoint = "https://api.msrc.microsoft.com/cvrf/v3.0/updates";

    private const int VendorFix = 2;
    private const int SeverityThreat = 3;

    public string Kind => Feeds.Msrc;

    /// <summary>
    /// The index names every month Microsoft has ever published (191 at capture time), so the cursor
    /// selects WHICH documents this run fetches rather than filtering inside one. That is a real
    /// request-level saving: normally the index plus nothing, or the index plus one month.
    ///
    /// <para>The index is read on every run even when nothing follows it. That is how "nothing new"
    /// gets established — the alternative is assuming it, which is how this module previously
    /// reported an empty sync as success.</para>
    /// </summary>
    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        var indexUri = new Uri(state.Endpoint ?? DefaultEndpoint);
        var index = await fetcher.GetStringAsync(indexUri, ct);

        var months = MonthsAfter(index, FeedCursor.Read(state.Cursor).Semantic);

        if (months.Count == 0)
            return new NormalizedBatch { Cursor = state.Cursor };

        var retrievedAt = DateTimeOffset.UtcNow;
        var advisories = new List<NormalizedAdvisory>();
        var patches = new List<NormalizedPatch>();
        string? cursor = null;

        // Oldest first, so the cursor ends on the newest month actually ingested. A failure part-way
        // through leaves the whole run failed and the cursor held (ContentSyncService), so the next
        // run re-reads from the same place rather than skipping the months it did not reach.
        foreach (var month in months)
        {
            ct.ThrowIfCancellationRequested();

            var batch = Parse(await fetcher.GetStringAsync(new Uri(month.CvrfUrl), ct), retrievedAt);
            advisories.AddRange(batch.Advisories);
            patches.AddRange(batch.Patches);
            cursor = batch.Cursor ?? month.Id;
        }

        return new NormalizedBatch { Advisories = advisories, Patches = patches, Cursor = cursor };
    }

    /// <summary>
    /// The months to fetch: those published after the month the cursor names, oldest first.
    ///
    /// <para>A cursor the index no longer carries — Microsoft renaming or withdrawing a month —
    /// falls back to the newest month alone rather than to everything. Re-ingesting 191 documents
    /// because one id moved would be a self-inflicted outage; missing older months is visible in the
    /// catalogue, which is the recoverable direction.</para>
    ///
    /// <para>A null cursor is a first run and also takes the newest month only. Backfill is a
    /// deliberate operator action, not something a fresh install does on its own.</para>
    /// </summary>
    public static IReadOnlyList<MsrcMonth> MonthsAfter(string json, string? cursorId)
    {
        // Both fallbacks DELEGATE to NewestMonth rather than re-deriving "newest" here. That answer
        // carries a subtlety — InitialReleaseDate, never CurrentReleaseDate, see below — which must
        // not exist in two places where one copy can be corrected and the other left behind. It also
        // keeps NewestMonth on the production path, so the tests that pin it still guard real code.
        if (cursorId is null)
            return [NewestMonth(json)];

        using var doc = JsonDocument.Parse(json);

        var all = doc.RootElement.Array("value")
            .Select(v => (Id: v.StringOrNull("ID"), Url: v.StringOrNull("CvrfUrl"),
                          Released: v.DateTimeOffsetOrNull("InitialReleaseDate")))
            .Where(v => v.Id is not null && v.Url is not null)
            .OrderBy(v => v.Released ?? DateTimeOffset.MinValue)
            .ToList();

        var at = all.FindIndex(v => string.Equals(v.Id, cursorId, StringComparison.OrdinalIgnoreCase));

        // Not found — including the empty-index case, where NewestMonth throws the format-change
        // error rather than letting an unusable index pass as "nothing new".
        if (at < 0)
            return [NewestMonth(json)];

        return all.Skip(at + 1).Select(v => new MsrcMonth(v.Id!, v.Url!)).ToList();
    }

    /// <summary>
    /// Picks the month a sync fetches, by <c>InitialReleaseDate</c>.
    ///
    /// <para>Deliberately NOT <c>CurrentReleaseDate</c>: months are revised in batches, so several
    /// share the same value — at capture time 2026-Apr, 2026-Jul and 2026-Aug all read
    /// <c>2026-08-20</c>. A max over that field therefore depends on array order and can select a
    /// four-month-old document. <c>InitialReleaseDate</c> is when the month was published, which is
    /// what "newest month" means.</para>
    ///
    /// <para>Which months a sync fetches beyond the newest is incrementality, and it is decided by
    /// <see cref="MonthsAfter"/> from the stored cursor. This method remains the first-run and
    /// cursor-not-found answer: newest month only.</para>
    /// </summary>
    public static MsrcMonth NewestMonth(string json)
    {
        using var doc = JsonDocument.Parse(json);

        var newest = doc.RootElement.Array("value")
            .Select(v => (Id: v.StringOrNull("ID"), Url: v.StringOrNull("CvrfUrl"),
                          Released: v.DateTimeOffsetOrNull("InitialReleaseDate")))
            .Where(v => v.Id is not null && v.Url is not null)
            .OrderByDescending(v => v.Released ?? DateTimeOffset.MinValue)
            .FirstOrDefault();

        return newest.Id is null || newest.Url is null
            ? throw new InvalidOperationException(
                "The msrc monthly index carried no usable entries. The endpoint's format has "
                + "changed — refusing to report an empty sync as success.")
            : new MsrcMonth(newest.Id, newest.Url);
    }

    public static NormalizedBatch Parse(string json, DateTimeOffset retrievedAt)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Shape check, not a tolerant read — see the class summary.
        if (root.Prop("Vulnerability")?.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException(
                "The msrc document carried no 'Vulnerability' array. The endpoint's format has "
                + "changed — refusing to report an empty sync as success.");

        var products = ReadProductTree(root);
        var advisories = new List<NormalizedAdvisory>();
        var patchesByKb = new Dictionary<string, PatchAccumulator>(StringComparer.OrdinalIgnoreCase);
        var entries = 0;

        foreach (var vuln in root.Array("Vulnerability"))
        {
            entries++;

            var cve = vuln.StringOrNull("CVE");
            if (string.IsNullOrEmpty(cve))
                continue;

            // 0001-01-01 with ReleaseDateSpecified=false is a .NET default serialized as a date.
            // Parsing it yields a real timestamp in year 1 that sorts ahead of everything and reads
            // as a genuine publication date. Unstated stays null (HARD-PROBLEMS #8).
            var released = vuln.BoolOrNull("ReleaseDateSpecified") == true
                ? vuln.DateTimeOffsetOrNull("ReleaseDate")
                : null;

            var score = vuln.Array("CVSSScoreSets").FirstOrDefault();
            var vector = score.ValueKind == JsonValueKind.Object ? score.StringOrNull("Vector") : null;

            var provenance = new[]
            {
                new ProvenanceEntry(
                    Feeds.Msrc, retrievedAt, SourceRecordId: cve,
                    Url: $"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"),
            };

            var affects = new Dictionary<(string Package, string? Platform), NormalizedAffect>();
            var kbs = new List<string>();

            foreach (var rem in vuln.Array("Remediations"))
            {
                if (rem.DoubleOrNull("Type") != VendorFix)
                    continue;

                var description = rem.Prop("Description")?.StringOrNull("Value");
                var fixedBuild = rem.StringOrNull("FixedBuild");
                var restart = rem.Prop("RestartRequired")?.StringOrNull("Value");
                var productIds = rem.Array("ProductID").Select(p => p.GetString()).Where(p => p is not null).ToList();

                foreach (var productId in productIds)
                {
                    if (!products.TryGetValue(productId!, out var product) || fixedBuild is null)
                        continue;

                    // The product is both the package and the platform on Windows: MSRC states a
                    // fixed BUILD for a named product, with no separate package axis the way a
                    // distro has (openssl on ubuntu:22.04).
                    var key = (product, (string?)product);

                    // Two KBs — typically a cumulative and a security-only update — can fix one CVE
                    // on one product at different builds. advisory_affects is unique on
                    // (advisory, package, ecosystem, platform), so keep the LOWEST: a host that
                    // installed either KB is fixed, and the lower build is where that becomes true.
                    if (affects.TryGetValue(key, out var existing)
                        && CompareBuilds(existing.FixedVersion, fixedBuild) <= 0)
                        continue;

                    affects[key] = new NormalizedAffect(
                        PackageName: product,
                        Ecosystem: Ecosystems.Windows,
                        Platform: product,
                        FixedVersion: fixedBuild,
                        Backported: false);
                }

                if (!IsKbNumber(description))
                    continue;

                var vendorId = NormalizeKb(description!);
                kbs.Add(vendorId);

                if (!patchesByKb.TryGetValue(vendorId, out var acc))
                    patchesByKb[vendorId] = acc = new PatchAccumulator(vendorId, released, retrievedAt);

                acc.Title ??= productIds
                    .Select(p => products.GetValueOrDefault(p!))
                    .FirstOrDefault(p => p is not null);

                // Yes / No / Maybe. Only an explicit "No" is a vendor statement that no reboot is
                // needed; "Maybe" must not be planned as no-reboot (HARD-PROBLEMS #8).
                acc.RequiresReboot |= restart is not null
                    && !string.Equals(restart, "No", StringComparison.OrdinalIgnoreCase);

                foreach (var superseded in Supersedences(rem.StringOrNull("Supercedence")))
                    acc.Supersedes.Add(superseded);
            }

            advisories.Add(new NormalizedAdvisory
            {
                Source = Feeds.Msrc,
                ExternalId = cve,
                Title = vuln.Prop("Title")?.StringOrNull("Value") ?? cve,
                Severity = MapSeverity(SeverityOf(vuln)),
                PublishedAt = released,
                CvssBaseScore = score.ValueKind == JsonValueKind.Object ? score.DoubleOrNull("BaseScore") : null,
                CvssVector = vector,
                CvssVersion = VersionFromVector(vector),
                CvssSource = vector is null ? null : Feeds.Msrc,
                SourceMetadataJson = kbs.Count > 0
                    ? JsonSerializer.Serialize(new { kbs = kbs.Distinct().ToArray() })
                    : null,
                Provenance = provenance,
                Affects = affects.Values.ToList(),
            });
        }

        if (entries > 0 && advisories.Count == 0)
            throw new InvalidOperationException(
                $"The msrc document carried {entries} vulnerabilities but none had a 'CVE'. The "
                + "endpoint's format has changed — refusing to report an empty sync as success.");

        return new NormalizedBatch
        {
            Advisories = advisories,
            Patches = patchesByKb.Values.Select(a => a.Build()).ToList(),
            Cursor = root.Prop("DocumentTracking")?.Prop("Identification")?.Prop("ID")?.StringOrNull("Value"),
        };
    }

    /// <summary>ProductID → human name. A remediation names products only by opaque id.</summary>
    private static Dictionary<string, string> ReadProductTree(JsonElement root)
    {
        var products = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var product in root.Prop("ProductTree")?.Array("FullProductName") ?? [])
        {
            var id = product.StringOrNull("ProductID");
            var name = product.StringOrNull("Value");
            if (id is not null && name is not null)
                products[id] = name;
        }

        return products;
    }

    /// <summary>Severity is a Threat of type 3, not a member of the vulnerability.</summary>
    private static string? SeverityOf(JsonElement vuln) =>
        vuln.Array("Threats")
            .Where(t => t.DoubleOrNull("Type") == SeverityThreat)
            .Select(t => t.Prop("Description")?.StringOrNull("Value"))
            .FirstOrDefault(d => d is not null);

    /// <summary>
    /// A KB number, not a label. Microsoft puts <c>"Release Notes"</c> and product-family names in
    /// the same field for non-Windows products; those must never become a patch id.
    /// </summary>
    private static bool IsKbNumber(string? value) =>
        value is not null
        && Regex.IsMatch(value, @"^(KB)?\d{6,8}$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));

    private static IEnumerable<string> Supersedences(string? raw) =>
        raw is null
            ? []
            : Regex.Matches(raw, @"\d{6,8}", RegexOptions.None, TimeSpan.FromSeconds(1))
                .Select(m => NormalizeKb(m.Value));

    /// <summary>
    /// Four-part Windows build compare, numeric per segment — <c>10.0.20348.5440</c> is older than
    /// <c>10.0.20348.5499</c>, which a string compare also happens to get right here and would get
    /// wrong at <c>….999</c> vs <c>…​.1000</c>. Non-numeric versions (Teams, VS Code) fall back to
    /// an ordinal compare, which is enough to make the choice deterministic.
    /// </summary>
    private static int CompareBuilds(string? left, string? right)
    {
        if (left is null || right is null)
            return string.CompareOrdinal(left, right);

        var a = left.Split('.');
        var b = right.Split('.');

        for (var i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            var hasA = i < a.Length && int.TryParse(a[i], out var na);
            var hasB = i < b.Length && int.TryParse(b[i], out var nb);
            if (!hasA || !hasB)
                return string.CompareOrdinal(left, right);

            na = int.Parse(a[i]);
            nb = int.Parse(b[i]);
            if (na != nb)
                return na.CompareTo(nb);
        }

        return 0;
    }

    private static string? VersionFromVector(string? vector) =>
        vector?.StartsWith("CVSS:", StringComparison.Ordinal) == true
            ? vector[5..].Split('/')[0]
            : null;

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

    private sealed class PatchAccumulator(string vendorId, DateTimeOffset? released, DateTimeOffset retrievedAt)
    {
        public string? Title { get; set; }
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
