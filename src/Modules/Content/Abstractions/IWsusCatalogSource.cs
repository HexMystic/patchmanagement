using PatchManagement.Content.Abstractions;

namespace PatchManagement.Content.Abstractions;

/// <summary>
/// Reads the wsusscn2 offline-sync catalogue: the update GRAPH plus the per-revision detail that
/// lives in a different cab from it.
///
/// <para><b>This replaced <c>IWsusPackageSource</c>, which could not express the format.</b> That
/// seam handed back a single extracted <c>package.xml</c> stream, on the assumption that the
/// catalogue was one file. It is not: <c>package.xml</c> is the graph only, and every field a patch
/// needs — the KB, the title, the reboot flag, and the software-vs-category discriminator — lives in
/// one of 74 sibling shards, keyed by <c>RevisionId</c>. A one-stream seam cannot reach them, which
/// is why the rewrite starts here rather than in the parser.</para>
///
/// <para>The split is what makes the two halves testable apart: the parser runs against a fake
/// source over captured XML with no cab involved, and the real reader is exercised against the
/// actual 658&#160;MB cab in the integration suite. Testing only the parser is what produced the
/// false "fully tested independently of this extractor" claim this module already had to strike.</para>
/// </summary>
public interface IWsusCatalogSource : IAsyncDisposable
{
    /// <summary>The update graph — <c>package.cab → package.xml</c>. Streamed; it is ~115&#160;MB.</summary>
    Task<Stream> OpenPackageXmlAsync(CancellationToken ct);

    /// <summary>
    /// The per-revision detail blobs for one <c>RevisionId</c>, or null when the catalogue has no
    /// entry for it. Null means "the graph references a revision the shards do not carry", which is
    /// a real condition; an unreadable SHARD is not, and throws.
    /// </summary>
    Task<WsusRevision?> OpenRevisionAsync(long revisionId, CancellationToken ct);
}
