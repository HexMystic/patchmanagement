using System.Text.Json;
using System.Xml.Linq;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// wsusscn2.cab connector — the Windows APPLICABILITY/patch side of ADR 0008 (MSRC is the CVE
/// overlay). It ingests the offline-sync <c>package.xml</c> catalogue into <c>patches</c>
/// (source = <c>wsusscn2</c>) and the supersedence DAG (<c>patch_supersedence</c>): each update's
/// <c>SupersededBy</c> revisions are inverted into "the newer patch supersedes this older one", so
/// Phase 6 can resolve a missing patch to its effective head (HARD-PROBLEMS #4).
///
/// SCOPE / HONESTY: the valuable, testable part — turning the catalogue XML into patches + edges —
/// is implemented here and fully covered by tests against a sample <c>package.xml</c>. Physically
/// decompressing the ~627&#160;MB nested CAB (<c>wsusscn2.cab</c> → <c>package.cab</c> →
/// <c>package.xml</c>) is delegated to <see cref="IWsusPackageSource"/>; the production extractor
/// (<see cref="PatchManagement.Content.Http.ExpandCabPackageSource"/>) shells out to Windows
/// <c>expand.exe</c> and has NOT been exercised against the full cab in this slice — see its TODO.
/// Localized update TITLES live in per-language cabs inside the package and are not read here; a KB
/// or UpdateId identifies each patch, and richer titles are a documented follow-up.
/// </summary>
public sealed class Wsusscn2Connector(IWsusPackageSource packageSource) : IContentConnector
{
    public string Kind => Feeds.Wsusscn2;

    public async Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(state.Endpoint))
            throw new InvalidOperationException(
                "wsusscn2 sync requires content_sources.endpoint to point at the local wsusscn2.cab "
                + "(the cab is downloaded out-of-band, never re-fetched).");

        await using var xml = await packageSource.OpenPackageXmlAsync(state.Endpoint, ct);
        return Parse(xml, DateTimeOffset.UtcNow);
    }

    /// <summary>Pure parse of an offline-sync package.xml stream — the tested normalization path.</summary>
    public static NormalizedBatch Parse(Stream packageXml, DateTimeOffset retrievedAt)
    {
        var doc = XDocument.Load(packageXml);
        return Parse(doc, retrievedAt);
    }

    public static NormalizedBatch Parse(XDocument doc, DateTimeOffset retrievedAt)
    {
        // Namespace-agnostic: match by local name so we tolerate the OfflineSync namespace being
        // present or absent, and minor schema drift between catalogue vintages.
        var updates = doc.Descendants().Where(e => e.Name.LocalName == "Update").ToList();

        var parsed = new List<ParsedUpdate>();
        var byRevision = new Dictionary<string, ParsedUpdate>(StringComparer.OrdinalIgnoreCase);

        foreach (var u in updates)
        {
            var kb = Value(u, "KBArticleID");
            var isSoftware = Value(u, "IsSoftware");
            // Skip category/detectoid rows: real catalogues carry thousands. Keep anything with a KB
            // or explicitly flagged software.
            if (string.IsNullOrEmpty(kb) && !string.Equals(isSoftware, "true", StringComparison.OrdinalIgnoreCase))
                continue;

            var updateId = Value(u, "UpdateId");
            var revisionId = Value(u, "RevisionId");
            var vendorId = !string.IsNullOrEmpty(kb) ? NormalizeKb(kb) : updateId;
            if (string.IsNullOrEmpty(vendorId))
                continue;

            var supersededByRevisions = u.Descendants()
                .Where(e => e.Name.LocalName is "Revision" or "SupersededBy")
                .SelectMany(e => e.Name.LocalName == "SupersededBy" ? e.Elements() : [e])
                .Select(e => (string?)e.Attribute("Id") ?? Value(e, "Id"))
                .Where(id => !string.IsNullOrEmpty(id))
                .Select(id => id!)
                .ToList();

            var pu = new ParsedUpdate
            {
                VendorId = vendorId,
                UpdateId = updateId,
                RevisionId = revisionId,
                Kb = kb,
                Title = Value(u, "Title") ?? (kb is not null ? $"{NormalizeKb(kb)} update" : vendorId),
                RequiresReboot = RebootFrom(Value(u, "RebootBehavior")),
                Reversible = string.Equals(Value(u, "Uninstallable"), "true", StringComparison.OrdinalIgnoreCase),
                SupersededByRevisions = supersededByRevisions,
            };

            parsed.Add(pu);
            if (!string.IsNullOrEmpty(revisionId))
                byRevision[revisionId] = pu;
        }

        // Invert SupersededBy (per the superseded update) into Supersedes (on the superseding patch):
        // if U says "superseded by revision R" and R is a known patch, then R supersedes U.
        var supersedes = parsed.ToDictionary(p => p.VendorId, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        foreach (var u in parsed)
        foreach (var rev in u.SupersededByRevisions)
            if (byRevision.TryGetValue(rev, out var newer) && !string.Equals(newer.VendorId, u.VendorId, StringComparison.OrdinalIgnoreCase))
                supersedes[newer.VendorId].Add(u.VendorId);

        var patches = parsed.Select(p => new NormalizedPatch
        {
            Source = Feeds.Wsusscn2,
            VendorId = p.VendorId,
            Title = p.Title,
            Reversible = p.Reversible,
            RequiresReboot = p.RequiresReboot,
            Classification = "Update",
            SourceMetadataJson = JsonSerializer.Serialize(new
            {
                updateId = p.UpdateId,
                revisionId = p.RevisionId,
                kb = p.Kb,
            }),
            Provenance = [new ProvenanceEntry(Feeds.Wsusscn2, retrievedAt, SourceRecordId: p.UpdateId ?? p.VendorId)],
            Supersedes = supersedes[p.VendorId].ToList(),
        }).ToList();

        var cursor = doc.Root?.Attribute("PackageId")?.Value;

        return new NormalizedBatch { Patches = patches, Cursor = cursor };
    }

    private static string NormalizeKb(string kb)
    {
        var digits = kb.TrimStart('K', 'B', 'k', 'b');
        return $"KB{digits}";
    }

    // AlwaysRequiresReboot / CanRequestReboot → reboot; NeverReboots / absent → no reboot (safe default).
    private static bool RebootFrom(string? behavior) => behavior?.ToLowerInvariant() switch
    {
        "alwaysrequiresreboot" => true,
        "canrequestreboot" => true,
        _ => false,
    };

    // Reads an attribute OR a child element of the given local name (catalogues use both forms).
    private static string? Value(XElement e, string localName)
    {
        var attr = e.Attributes().FirstOrDefault(a => a.Name.LocalName == localName);
        if (attr is not null)
            return attr.Value;
        var child = e.Elements().FirstOrDefault(c => c.Name.LocalName == localName);
        return child?.Value;
    }

    private sealed class ParsedUpdate
    {
        public required string VendorId { get; init; }
        public string? UpdateId { get; init; }
        public string? RevisionId { get; init; }
        public string? Kb { get; init; }
        public required string Title { get; init; }
        public bool RequiresReboot { get; init; }
        public bool Reversible { get; init; }
        public required List<string> SupersededByRevisions { get; init; }
    }
}
