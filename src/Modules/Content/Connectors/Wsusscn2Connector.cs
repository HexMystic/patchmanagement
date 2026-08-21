using System.Globalization;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// wsusscn2.cab connector — the Windows APPLICABILITY/patch side of ADR 0008 (MSRC is the CVE
/// overlay). It ingests the offline-sync catalogue into <c>patches</c> (source = <c>wsusscn2</c>)
/// and the supersedence DAG (<c>patch_supersedence</c>): each update's <c>SupersededBy</c> revisions
/// are inverted into "the newer patch supersedes this older one", so Phase 6 can resolve a missing
/// patch to its effective head (HARD-PROBLEMS #4).
///
/// <para><b>Rewritten 2026-08-21 (D-504) against the real 658&#160;MB cab.</b> The previous parser
/// returned an <b>empty batch that the sync recorded as <c>ok</c></b> — on the feed that is the
/// source of truth for what a Windows host is missing. It looked for <c>KBArticleID</c>,
/// <c>Title</c>, <c>RebootBehavior</c> and <c>IsSoftware="true"</c> in <c>package.xml</c>, and the
/// real file contains <b>zero</b> occurrences of any of them across 137,091 updates: the graph
/// carries identity and relationships only.</para>
///
/// <para><b>Every one of those fields lives in a sibling shard, keyed by <c>RevisionId</c>:</b>
/// <c>c/&lt;n&gt;</c> holds <c>Properties/@UpdateType</c> — the real software-vs-category
/// discriminator, since <c>IsSoftware</c> is <c>"false"</c> throughout; <c>x/&lt;n&gt;</c> holds
/// <c>KBArticleID</c>, <c>MsrcSeverity</c> and <c>InstallationBehavior/@RebootBehavior</c>; and
/// <c>l/en/&lt;n&gt;</c> holds the title. Reaching them is why <c>IWsusPackageSource</c> — a seam that
/// could only hand back one <c>package.xml</c> — was replaced by
/// <see cref="IWsusCatalogSource"/>.</para>
///
/// <para><b><c>Uninstallable</c> does not exist in the catalogue at all</b> (zero occurrences across
/// every <c>c/</c> and <c>x/</c> blob in the shard measured). So <c>reversible</c> is <c>false</c> as
/// an honest "the vendor never said", which gates rollback OFF — the safe direction
/// (DIFFERENTIATORS #1), and a stated limit rather than a silent default.</para>
///
/// <para>The graph is streamed with <see cref="XmlReader"/> rather than loaded: it is ~115&#160;MB,
/// and <c>XDocument.Load</c> would hold the whole DOM per sync.</para>
/// </summary>
public sealed class Wsusscn2Connector(Func<string, IWsusCatalogSource> catalogFor) : IContentConnector
{
    public string Kind => Feeds.Wsusscn2;

    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(state.Endpoint))
            throw new InvalidOperationException(
                "wsusscn2 sync requires content_sources.endpoint to point at the local wsusscn2.cab "
                + "(the cab is downloaded out-of-band, never re-fetched).");

        // The catalogue is opened per sync because its path is per feed row, and disposed with it
        // because it materialises shards into a temp directory.
        await using var catalog = catalogFor(state.Endpoint);
        return await ParseAsync(catalog, DateTimeOffset.UtcNow, ct);
    }

    /// <summary>
    /// Walks the graph, joins each update to its shard blobs, and emits patches plus supersedence.
    /// Pure with respect to the catalogue seam, which is what lets it be tested against captured
    /// blobs with no cab, no native library and no platform dependency.
    /// </summary>
    public static async Task<NormalizedBatch> ParseAsync(
        IWsusCatalogSource source, DateTimeOffset retrievedAt, CancellationToken ct)
    {
        var parsed = new List<ParsedUpdate>();
        var byRevision = new Dictionary<long, ParsedUpdate>();
        var seen = 0;
        string? packageId;

        await using (var graph = await source.OpenPackageXmlAsync(ct))
        {
            using var reader = XmlReader.Create(graph, new XmlReaderSettings { IgnoreWhitespace = true });

            reader.MoveToContent();
            packageId = reader.GetAttribute("PackageId");

            while (!reader.EOF)
            {
                ct.ThrowIfCancellationRequested();

                if (reader.NodeType != XmlNodeType.Element || reader.LocalName != "Update")
                {
                    reader.Read();
                    continue;
                }

                // ReadFrom materialises ONE update and ADVANCES PAST IT, so the loop must not call
                // Read() as well — doing so silently skips every other update. The ~115 MB graph is
                // never resident. Namespace-agnostic: the real file is in the OfflineSync namespace,
                // older vintages are not.
                if (XNode.ReadFrom(reader) is not XElement update)
                    continue;

                seen++;

                if (!long.TryParse(Value(update, "RevisionId"), out var revisionId))
                    continue;

                var detail = await source.OpenRevisionAsync(revisionId, ct);
                if (detail is null)
                    continue;

                // The real discriminator. Detectoids (applicability probes) and Categories
                // (taxonomy) are not installable; a real catalogue carries thousands of each.
                if (!string.Equals(UpdateType(detail.Core), "Software", StringComparison.OrdinalIgnoreCase))
                    continue;

                var updateId = Value(update, "UpdateId");
                var kb = detail.Extended is null ? null : Value(detail.Extended, "KBArticleID");
                var vendorId = !string.IsNullOrEmpty(kb) ? NormalizeKb(kb) : updateId;
                if (string.IsNullOrEmpty(vendorId))
                    continue;

                var item = new ParsedUpdate
                {
                    VendorId = vendorId,
                    UpdateId = updateId,
                    RevisionId = revisionId,
                    Kb = kb,
                    Title = TitleOf(detail) ?? vendorId,
                    MsrcSeverity = AttributeAnywhere(detail.Extended, "MsrcSeverity"),
                    RequiresReboot = RebootFrom(RebootBehavior(detail.Extended)),
                    SupersededByRevisions = SupersededBy(update).ToList(),
                };

                parsed.Add(item);
                byRevision[revisionId] = item;
            }
        }

        // Invert SupersededBy (stated on the OLDER update) into Supersedes (carried by the NEWER
        // patch): if U says "superseded by revision R" and R is itself a patch here, R supersedes U.
        // An edge whose other end is absent produces nothing — a dangling vendor id would be a
        // relationship the catalogue does not support.
        // ONE KB, SEVERAL REVISIONS. A KB is re-issued as a new revision of the same update, and the
        // catalogue carries every revision. `patches` is unique on (source, vendor_id), so they must
        // collapse to one patch with their supersedence merged — emitting one row per revision would
        // have the store keep whichever landed last and the reported count describe nothing.
        var merged = new Dictionary<string, ParsedUpdate>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in parsed)
            merged[item.VendorId] = merged.TryGetValue(item.VendorId, out var existing)
                ? existing.MergedWith(item)
                : item;

        var supersedes = merged.Keys.ToDictionary(
            id => id,
            _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);

        foreach (var item in parsed)
        foreach (var revision in item.SupersededByRevisions)
            if (byRevision.TryGetValue(revision, out var newer)
                && !string.Equals(newer.VendorId, item.VendorId, StringComparison.OrdinalIgnoreCase))
                supersedes[newer.VendorId].Add(item.VendorId);

        var patches = merged.Values.Select(p => new NormalizedPatch
        {
            Source = Feeds.Wsusscn2,
            VendorId = p.VendorId,
            Title = p.Title,
            // The catalogue never states uninstallability — see the class summary.
            Reversible = false,
            RequiresReboot = p.RequiresReboot,
            Classification = "Update",
            SourceMetadataJson = JsonSerializer.Serialize(new
            {
                updateId = p.UpdateId,
                revisionId = p.RevisionId,
                kb = p.Kb,
                msrcSeverity = p.MsrcSeverity,
            }),
            Provenance = [new ProvenanceEntry(Feeds.Wsusscn2, retrievedAt, SourceRecordId: p.UpdateId ?? p.VendorId)],
            Supersedes = supersedes[p.VendorId].ToList(),
        }).ToList();

        // The defect this rewrite exists for: a catalogue full of updates that yields no patches is
        // a format change, and it previously passed as `ok` with the cursor advanced
        // (ADR 0022 mitigation (a)).
        if (seen > 0 && patches.Count == 0)
            throw new InvalidOperationException(
                $"The wsusscn2 catalogue carried {seen} updates but none resolved to a patch. The "
                + "cab's layout has changed — refusing to report an empty sync as success.");

        return new NormalizedBatch { Patches = patches, Cursor = packageId };
    }

    /// <summary>Finds an attribute on the element or any descendant — blobs arrive wrapped.</summary>
    private static string? AttributeAnywhere(XElement? element, string name) =>
        element?.DescendantsAndSelf()
            .Select(e => e.Attribute(name))
            .FirstOrDefault(a => a is not null)?.Value;

    private static string? UpdateType(XElement core) =>
        core.Descendants().FirstOrDefault(e => e.Name.LocalName == "Properties")
            ?.Attribute("UpdateType")?.Value
        ?? (core.Name.LocalName == "Properties" ? core.Attribute("UpdateType")?.Value : null);

    private static string? TitleOf(WsusRevision detail) =>
        detail.Localized?.Descendants().FirstOrDefault(e => e.Name.LocalName == "Title")?.Value;

    private static string? RebootBehavior(XElement? extended) =>
        extended?.Descendants().FirstOrDefault(e => e.Name.LocalName == "InstallationBehavior")
            ?.Attribute("RebootBehavior")?.Value;

    /// <summary>The revisions this update declares itself superseded BY, as ids.</summary>
    private static IEnumerable<long> SupersededBy(XElement update) =>
        update.Descendants()
            .Where(e => e.Name.LocalName == "SupersededBy")
            .SelectMany(e => e.Elements())
            .Select(e => e.Attribute("Id")?.Value)
            .Where(id => id is not null)
            .Select(id => long.TryParse(id, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)
                ? v
                : (long?)null)
            .Where(v => v.HasValue)
            .Select(v => v!.Value);

    private static string NormalizeKb(string kb)
    {
        var digits = kb.TrimStart('K', 'B', 'k', 'b');
        return $"KB{digits}";
    }

    // AlwaysRequiresReboot / CanRequestReboot → reboot; NeverReboots / absent → no reboot.
    private static bool RebootFrom(string? behavior) => behavior?.ToLowerInvariant() switch
    {
        "alwaysrequiresreboot" => true,
        "canrequestreboot" => true,
        _ => false,
    };

    // Reads an attribute OR a child element of the given local name (the catalogue uses both forms:
    // RevisionId is an attribute, KBArticleID is an element).
    private static string? Value(XElement e, string localName)
    {
        var attr = e.Attributes().FirstOrDefault(a => a.Name.LocalName == localName);
        if (attr is not null)
            return attr.Value;

        var child = e.Descendants().FirstOrDefault(c => c.Name.LocalName == localName);
        return child?.Value;
    }

    private sealed class ParsedUpdate
    {
        public required string VendorId { get; init; }
        public string? UpdateId { get; init; }
        public required long RevisionId { get; init; }
        public string? Kb { get; init; }
        public required string Title { get; init; }
        public string? MsrcSeverity { get; init; }
        public bool RequiresReboot { get; init; }
        public required List<long> SupersededByRevisions { get; init; }

        /// <summary>
        /// Fold a later revision of the SAME KB into this one. Reboot is OR-ed because any revision
        /// needing one means the patch does; the newest revision wins on identity and title, and the
        /// superseded-by lists are unioned so no edge is lost to the collapse.
        /// </summary>
        public ParsedUpdate MergedWith(ParsedUpdate other) => new()
        {
            VendorId = VendorId,
            UpdateId = other.RevisionId > RevisionId ? other.UpdateId : UpdateId,
            RevisionId = Math.Max(RevisionId, other.RevisionId),
            Kb = Kb ?? other.Kb,
            Title = other.RevisionId > RevisionId && other.Title != other.VendorId ? other.Title : Title,
            MsrcSeverity = MsrcSeverity ?? other.MsrcSeverity,
            RequiresReboot = RequiresReboot || other.RequiresReboot,
            SupersededByRevisions = [.. SupersededByRevisions.Union(other.SupersededByRevisions)],
        };
    }
}
