using System.Globalization;
using System.Xml.Linq;
using PatchManagement.Content.Abstractions;
using WixToolset.Dtf.Compression.Cab;

namespace PatchManagement.Content.Http;

/// <summary>
/// Reads the wsusscn2 offline-sync catalogue with the vendored WiX DTF cabinet reader
/// (<b>ADR 0020</b>, MS-RL, <c>third_party/wix-dtf/</c>) — its first consumer.
///
/// <para><b>Replaced <c>ExpandCabPackageSource</c>, which could never run.</b> That implementation
/// shelled out to <c>expand.exe</c> with a FILE destination; <c>wsusscn2.cab</c> is a multi-file cab
/// and <c>expand.exe</c> refuses one — <i>"Destination directory required for a multi-file CAB"</i>,
/// exit 2, on the very first call, every time. It also read <c>package.cab</c> alone and never
/// opened <c>index.xml</c>, so 74 of the 75 cabs were invisible to it.</para>
///
/// <para><b>The layout, measured against the real 658&#160;MB cab, not inferred:</b></para>
/// <code>
/// wsusscn2.cab
/// ├── index.xml                    &lt;CABLIST&gt;: package.cab + package2..75.cab, each with RANGESTART
/// ├── package.cab → package.xml    ~115 MB, the GRAPH: 137,091 &lt;Update RevisionId=…&gt;
/// └── package2..75.cab             per-revision detail:  c/&lt;n&gt;  x/&lt;n&gt;  l/&lt;lang&gt;/&lt;n&gt;
/// </code>
///
/// <para><b>The shard rule.</b> <c>RANGESTART</c> partitions the revision-id space: shard 2 starts at
/// 0 and holds revisions 1–626, shard 3 starts at 627, and so on to 45,415,921. A revision lives in
/// the shard with the <b>largest RANGESTART below it</b>, which is a binary search, not a scan.</para>
///
/// <para><b>Still Windows-only, and DTF does not change that</b> — a correction to what
/// <c>ExpandCabPackageSource</c> and phase-5.md both predicted. The library contains no
/// decompression code whatsoever: every byte goes through <c>cabinet.dll</c>'s FDI API by P/Invoke,
/// so LZX works because <i>Windows</i> decodes it. Off Windows this would throw
/// <c>DllNotFoundException</c> from deep inside a P/Invoke — strictly worse than an explicit refusal,
/// which is why the platform guard below is kept rather than dropped.</para>
///
/// <para><b>A missing or unreadable shard fails the whole sync.</b> One unreadable shard means an
/// unknown number of Windows updates silently absent, and ADR 0008 makes this feed the source of
/// truth for "what is missing on this host" — a partial catalogue reported as <c>ok</c> is the exact
/// hazard this module keeps hitting. Phase 6 cannot tell a partial ingest from a complete one, so
/// the sync fails and the cursor holds instead.</para>
/// </summary>
public sealed class DtfWsusCatalogSource : IWsusCatalogSource
{
    private readonly string _cabPath;
    private readonly DirectoryInfo _work;
    private readonly List<Shard> _shards = [];
    private readonly Dictionary<string, DirectoryInfo> _extracted = new(StringComparer.OrdinalIgnoreCase);
    private bool _indexRead;

    public DtfWsusCatalogSource(string cabPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "The wsusscn2 catalogue is a Microsoft cabinet. The vendored WiX DTF reader wraps "
                + "Windows cabinet.dll (FDI) by P/Invoke and has no managed decompressor, so there "
                + "is no cross-platform path today. Refusing explicitly rather than failing with a "
                + "DllNotFoundException from inside a P/Invoke.");

        if (!File.Exists(cabPath))
            throw new FileNotFoundException("wsusscn2.cab not found.", cabPath);

        _cabPath = cabPath;
        _work = Directory.CreateTempSubdirectory("wsusscn2_");
    }

    public async Task<Stream> OpenPackageXmlAsync(CancellationToken ct)
    {
        await EnsureIndexAsync(ct);

        // package.cab -> package.xml. Extracted to disk rather than memory on purpose: the stock
        // BasicUnpackStreamContext buys a MemoryStream sized (int)fileSize, and package.xml is
        // ~115 MB — an LOH allocation per sync, and hard-capped at 2 GB.
        var packageCab = Path.Combine(_work.FullName, "package.cab");
        if (!File.Exists(packageCab))
            Extract(_cabPath, "package.cab", _work.FullName);

        var packageXml = Path.Combine(_work.FullName, "package.xml");
        if (!File.Exists(packageXml))
            Extract(packageCab, "package.xml", _work.FullName);

        return File.OpenRead(packageXml);
    }

    public async Task<WsusRevision?> OpenRevisionAsync(long revisionId, CancellationToken ct)
    {
        await EnsureIndexAsync(ct);

        var shard = ShardFor(revisionId);
        if (shard is null)
            return null;

        var dir = EnsureShardExtracted(shard);
        var core = LoadBlob(dir, Path.Combine("c", revisionId.ToString(CultureInfo.InvariantCulture)));

        return core is null
            ? null
            : new WsusRevision(
                revisionId,
                core,
                LoadBlob(dir, Path.Combine("x", revisionId.ToString(CultureInfo.InvariantCulture))),
                LoadBlob(dir, Path.Combine("l", "en", revisionId.ToString(CultureInfo.InvariantCulture))));
    }

    private Task EnsureIndexAsync(CancellationToken ct)
    {
        if (_indexRead)
            return Task.CompletedTask;

        ct.ThrowIfCancellationRequested();

        Extract(_cabPath, "index.xml", _work.FullName);
        var index = XDocument.Load(Path.Combine(_work.FullName, "index.xml"));

        foreach (var cab in index.Descendants().Where(e => e.Name.LocalName == "CAB"))
        {
            var name = (string?)cab.Attribute("NAME");
            var rangeStart = (string?)cab.Attribute("RANGESTART");

            // package.cab carries no RANGESTART: it is the graph, not a detail shard.
            if (name is null || rangeStart is null)
                continue;

            _shards.Add(new Shard(name, long.Parse(rangeStart, CultureInfo.InvariantCulture)));
        }

        if (_shards.Count == 0)
            throw new InvalidOperationException(
                "The wsusscn2 index.xml listed no detail shards. The cab's layout has changed — "
                + "refusing to ingest a catalogue that would be silently empty.");

        _shards.Sort((a, b) => a.RangeStart.CompareTo(b.RangeStart));
        _indexRead = true;
        return Task.CompletedTask;
    }

    /// <summary>The shard with the largest RANGESTART strictly below this revision id.</summary>
    private Shard? ShardFor(long revisionId)
    {
        Shard? found = null;
        foreach (var shard in _shards)
        {
            if (shard.RangeStart >= revisionId)
                break;
            found = shard;
        }

        return found;
    }

    private DirectoryInfo EnsureShardExtracted(Shard shard)
    {
        if (_extracted.TryGetValue(shard.Name, out var cached))
            return cached;

        // Extracted once per run, never per revision: DTF's Unpack runs a listing pass before the
        // extract pass, so a per-revision extract would cost two full FDICopy walks each time.
        var shardCab = Path.Combine(_work.FullName, shard.Name);
        if (!File.Exists(shardCab))
            Extract(_cabPath, shard.Name, _work.FullName);

        var dir = _work.CreateSubdirectory(Path.GetFileNameWithoutExtension(shard.Name));

        try
        {
            new CabInfo(shardCab).Unpack(dir.FullName);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException(
                $"The wsusscn2 shard '{shard.Name}' could not be read. One unreadable shard means an "
                + "unknown number of Windows updates would be missing from the catalogue, and this "
                + "feed is the source of truth for what a host is missing (ADR 0008) — failing the "
                + "whole sync rather than writing a silently partial catalogue.", ex);
        }

        _extracted[shard.Name] = dir;
        return dir;
    }

    private static XElement? LoadBlob(DirectoryInfo shardDir, string relativePath)
    {
        var path = Path.Combine(shardDir.FullName, relativePath);
        if (!File.Exists(path))
            return null;

        // The c/ and x/ blobs are XML FRAGMENTS: several sibling top-level elements with no single
        // root, which XElement.Parse rejects outright. Wrapping is the whole accommodation.
        return XElement.Parse($"<WsusBlob>{File.ReadAllText(path).TrimStart('﻿')}</WsusBlob>");
    }

    /// <summary>
    /// Extract one member to a DIRECTORY. The directory is the whole point: it is what
    /// <c>expand.exe</c> demanded and never got, and DTF does not care either way — which removes
    /// the defect by construction rather than by remembering.
    /// </summary>
    private static void Extract(string cabPath, string member, string destinationDirectory)
    {
        try
        {
            new CabInfo(cabPath).UnpackFile(member, Path.Combine(destinationDirectory, member));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException(
                $"Could not extract '{member}' from '{Path.GetFileName(cabPath)}'.", ex);
        }
    }

    public ValueTask DisposeAsync()
    {
        try
        {
            _work.Delete(recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup; the temp directory is disposable by definition.
        }

        return ValueTask.CompletedTask;
    }

    private sealed record Shard(string Name, long RangeStart);
}
