using System.Xml.Linq;
using PatchManagement.Content.Abstractions;
using PatchManagement.TestSupport;

namespace PatchManagement.Content.Tests;

/// <summary>
/// Serves the captured wsusscn2 slice from <c>Samples/wsusscn2/</c> — real bytes taken from the real
/// cab, laid out exactly as the shards lay them out (<c>c/&lt;n&gt;</c>, <c>x/&lt;n&gt;</c>,
/// <c>l/en/&lt;n&gt;</c>). See <c>Samples/PROVENANCE.md</c>.
///
/// <para>This is a fake SOURCE, not a fake payload. The distinction matters and is the reason the
/// seam was reshaped: the cab reading is exercised for real against the 658&#160;MB file in the
/// integration suite, while the parser is exercised here with no cab, no native library and no
/// platform dependency. Neither half is left assumed.</para>
/// </summary>
internal sealed class FakeWsusCatalogSource : IWsusCatalogSource
{
    private static string Root => RepoPaths.Source(
        "tests", "PatchManagement.Content.Tests", "Samples", "wsusscn2");

    /// <summary>Revisions the fake was asked for — lets a test assert the graph drove the lookups.</summary>
    public List<long> Requested { get; } = [];

    public Task<Stream> OpenPackageXmlAsync(CancellationToken ct)
    {
        var path = Path.Combine(Root, "package.xml");

        if (!File.Exists(path))
            throw new FileNotFoundException(
                "The captured wsusscn2 package.xml is missing — this test would otherwise parse "
                + "nothing and pass. Samples are real bytes; do NOT hand-write a replacement.",
                path);

        return Task.FromResult<Stream>(File.OpenRead(path));
    }

    public Task<WsusRevision?> OpenRevisionAsync(long revisionId, CancellationToken ct)
    {
        Requested.Add(revisionId);

        var core = Load("c", revisionId);
        if (core is null)
            return Task.FromResult<WsusRevision?>(null);

        return Task.FromResult<WsusRevision?>(new WsusRevision(
            revisionId, core, Load("x", revisionId), Load(Path.Combine("l", "en"), revisionId)));
    }

    private static XElement? Load(string family, long revisionId)
    {
        var path = Path.Combine(Root, family, revisionId.ToString());
        if (!File.Exists(path))
            return null;

        // The c/ and x/ blobs are XML FRAGMENTS — several top-level elements, no single root — so
        // they are wrapped before parsing, exactly as the real source does.
        return XElement.Parse($"<WsusBlob>{File.ReadAllText(path).TrimStart('﻿')}</WsusBlob>");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
