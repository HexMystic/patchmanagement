using PatchManagement.Content.Abstractions;
using PatchManagement.Content.Http;
using PatchManagement.TestSupport;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// <see cref="DtfWsusCatalogSource"/> against the real <c>lab/content/wsusscn2.cab</c> — 658&#160;MB,
/// fetched in Phase 0, gitignored.
///
/// <para><b>This is the half that was actually broken, and it had never run.</b> The previous
/// extractor shelled out to <c>expand.exe</c> with a FILE destination, which a multi-file cab
/// refuses outright (exit 2, "Destination directory required for a multi-file CAB") — so the first
/// call failed every time. It also read only <c>package.cab</c>, leaving 74 of the 75 cabs unopened.
/// Neither defect was reachable by a parser test, and testing the parser alone is exactly what
/// produced the false "fully tested independently of this extractor" claim this module had to
/// strike. So the extractor is exercised here, against the real artifact.</para>
///
/// <para><b>These tests FAIL rather than skip when the cab is absent</b>, matching this project's
/// posture everywhere else: a suite that quietly skips its only real-world coverage reports green
/// while proving nothing. The cab is fetched out of band (Phase 0, <c>scripts/verify-env.ps1</c>).</para>
///
/// <para>Windows-only by necessity, not by choice: the vendored WiX DTF reader has no managed
/// decompressor and P/Invokes <c>cabinet.dll</c>, so the LZX decoding is done by the OS.</para>
/// </summary>
public sealed class Wsusscn2CatalogTests
{
    /// <summary>Revision 500 sits in shard 2 (revisions 1-626) and is a Software update.</summary>
    private const long KnownRevision = 500;

    /// <summary>
    /// The cab is gitignored and 658&#160;MB, so it is fetched once into the MAIN checkout and not
    /// duplicated per worktree — the same arrangement WORKFLOW &#167;3 describes for Docker infra.
    /// A worktree therefore looks beside itself, up past <c>.claude/worktrees/&lt;name&gt;</c>, rather
    /// than pretending the file should be local.
    /// </summary>
    private static string CabPath()
    {
        var local = RepoPaths.Source("lab", "content", "wsusscn2.cab");
        if (File.Exists(local))
            return local;

        var root = RepoPaths.RepoRoot().FullName;
        var marker = Path.Combine(".claude", "worktrees");
        var index = root.IndexOf(marker, StringComparison.OrdinalIgnoreCase);

        if (index > 0)
        {
            var main = Path.Combine(root[..index].TrimEnd(Path.DirectorySeparatorChar),
                                    "lab", "content", "wsusscn2.cab");
            if (File.Exists(main))
                return main;
        }

        throw new FileNotFoundException(
            "wsusscn2.cab was not found in this worktree or in the main checkout, so the ONLY "
            + "coverage of the cab extractor cannot run. This FAILS rather than skips deliberately: "
            + "the extractor shipped broken once precisely because nothing exercised it, and a "
            + "silent skip would report green over that same hole. Fetch the cab (Phase 0).",
            local);
    }

    [Fact]
    public async Task The_index_resolves_a_revision_to_its_shard_and_reads_the_blob()
    {
        await using var catalog = new DtfWsusCatalogSource(CabPath());

        var revision = await catalog.OpenRevisionAsync(KnownRevision, CancellationToken.None);

        Assert.NotNull(revision);
        Assert.Equal(KnownRevision, revision!.RevisionId);

        // c/<n> carries the discriminator the whole rewrite turns on. Reading it here proves the
        // full chain: index.xml parsed, RANGESTART resolved to package2.cab, that shard extracted
        // from a MULTI-FILE cab, and an LZX-compressed member decoded.
        Assert.Contains(
            "Software",
            revision.Core.ToString(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The graph is the other cab in the chain (<c>wsusscn2.cab → package.cab → package.xml</c>) and
    /// is ~115&#160;MB, so it is streamed rather than buffered. Reading its opening element is enough
    /// to prove the nested extraction worked.
    /// </summary>
    [Fact]
    public async Task The_package_graph_opens_as_a_readable_stream()
    {
        await using var catalog = new DtfWsusCatalogSource(CabPath());

        await using var graph = await catalog.OpenPackageXmlAsync(CancellationToken.None);
        using var reader = new StreamReader(graph);

        var head = new char[512];
        var read = await reader.ReadAsync(head, CancellationToken.None);

        Assert.True(read > 0, "package.xml opened but yielded no bytes.");
        Assert.Contains("OfflineSyncPackage", new string(head, 0, read), StringComparison.Ordinal);
    }

    /// <summary>
    /// A revision id beyond anything the catalogue carries has no blob. Null is the honest answer —
    /// the graph can legitimately reference revisions the shards do not detail — and it must not be
    /// confused with an unreadable shard, which throws.
    /// </summary>
    [Fact]
    public async Task A_revision_the_catalogue_does_not_carry_returns_null()
    {
        await using var catalog = new DtfWsusCatalogSource(CabPath());

        Assert.Null(await catalog.OpenRevisionAsync(long.MaxValue, CancellationToken.None));
    }

    /// <summary>
    /// The end-to-end claim, and the one that closes D-504: the connector produces real patches from
    /// the real cab. Bounded to the first shard's revision range so the test stays minutes rather
    /// than hours — extracting all 75 shards is a full sync, not a test.
    /// </summary>
    [Fact]
    public async Task The_connector_produces_patches_from_the_real_cab()
    {
        await using var catalog = new BoundedCatalog(new DtfWsusCatalogSource(CabPath()), maxRevision: 626);

        var batch = await Connectors.Wsusscn2Connector.ParseAsync(
            catalog, DateTimeOffset.UtcNow, CancellationToken.None);

        Assert.NotEmpty(batch.Patches);
        Assert.All(batch.Patches, p => Assert.False(string.IsNullOrWhiteSpace(p.VendorId)));

        // The cursor is the catalogue's own PackageId — a real root attribute of the real file.
        Assert.False(string.IsNullOrWhiteSpace(batch.Cursor));
    }

    /// <summary>
    /// Caps revision lookups so the end-to-end test touches one shard instead of all 74. It narrows
    /// the RANGE, never the behaviour: every lookup within the range goes through the real
    /// <see cref="DtfWsusCatalogSource"/>, real cab and real decompression.
    /// </summary>
    private sealed class BoundedCatalog(IWsusCatalogSource inner, long maxRevision) : IWsusCatalogSource
    {
        public Task<Stream> OpenPackageXmlAsync(CancellationToken ct) => inner.OpenPackageXmlAsync(ct);

        public Task<WsusRevision?> OpenRevisionAsync(long revisionId, CancellationToken ct) =>
            revisionId > maxRevision
                ? Task.FromResult<WsusRevision?>(null)
                : inner.OpenRevisionAsync(revisionId, ct);

        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
}
