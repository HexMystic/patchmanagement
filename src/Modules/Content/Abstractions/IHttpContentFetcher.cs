namespace PatchManagement.Content.Abstractions;

/// <summary>
/// The seam that lets connectors be tested against recorded/sample payloads instead of live APIs.
/// Production wiring is a thin <c>HttpClient</c> wrapper with an enforced timeout; tests supply a
/// fake that returns fixture bytes. Nothing here carries credentials — the content feeds are public
/// (CLAUDE.md NEVER #1).
/// </summary>
public interface IHttpContentFetcher
{
    /// <summary>GET the resource as text (JSON feeds: NVD, KEV, EPSS, USN, DSA, RHSA, MSRC).</summary>
    Task<string> GetStringAsync(Uri uri, CancellationToken ct);

    /// <summary>GET the resource as a stream (binary feeds, e.g. a hosted wsusscn2.cab mirror).</summary>
    Task<Stream> GetStreamAsync(Uri uri, CancellationToken ct);
}
