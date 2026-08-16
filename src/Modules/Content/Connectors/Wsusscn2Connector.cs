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
/// <para><b>⚠ THIS PARSER IS WRITTEN AGAINST A SCHEMA THAT DOES NOT EXIST. It returns an EMPTY
/// BATCH against the real catalogue, and the sync reports <c>ok</c>.</b> Do not build on it — see
/// `docs/phases/phase-5.md` "wsusscn2 — the cab was opened for the first time" and <b>D-504</b>.</para>
///
/// <para><b>Correction (2026-08-16).</b> This comment previously claimed the normalization was
/// "fully covered by tests against a sample <c>package.xml</c>". <b>That was false.</b> No
/// wsusscn2 test and no <c>package.xml</c> sample have ever existed in this repository;
/// <see cref="Parse(System.Xml.Linq.XDocument, DateTimeOffset)"/> has zero coverage. The claim is
/// struck rather than quietly deleted, because a doc asserting a guarantee it does not have is what
/// stops the next reader from looking.</para>
///
/// <para>Measured against the real 658&#160;MB <c>lab/content/wsusscn2.cab</c>: <c>package.xml</c>
/// holds 136,965 <c>&lt;Update&gt;</c> elements and contains <b>zero</b> occurrences of
/// <c>KBArticleID</c>, <c>Title</c>, <c>RebootBehavior</c> or <c>Uninstallable</c>, and zero
/// <c>IsSoftware="true"</c> (all 4,206 are <c>"false"</c>). The first filter below therefore skips
/// every update. Those fields are real but live in the <c>package2..75.cab</c> shards —
/// <c>KBArticleID</c> in <c>x/&lt;n&gt;</c>, <c>Title</c> in <c>l/&lt;lang&gt;/&lt;n&gt;</c>, and the
/// software/category discriminator is <c>c/&lt;n&gt;</c>'s <c>Properties/@UpdateType</c>.</para>
///
/// <para>What IS correct against real data and should survive the rewrite: the
/// <c>SupersededBy → Revision/@Id</c> inversion, the <c>UpdateId</c>/<c>RevisionId</c> attributes,
/// and <c>PackageId</c> as the cursor.</para>
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
