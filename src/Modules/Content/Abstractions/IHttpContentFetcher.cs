namespace PatchManagement.Content.Abstractions;

/// <summary>
/// The seam that lets connectors be tested against recorded/sample payloads instead of live APIs.
/// Production wiring is a thin <c>HttpClient</c> wrapper with an enforced timeout; tests supply a
/// fake that returns fixture bytes. Nothing here carries credentials — the content feeds are public
/// (CLAUDE.md NEVER #1).
/// </summary>
public interface IHttpContentFetcher
{
    /// <summary>GET the resource as text (text feeds: NVD, KEV, EPSS, USN, RHSA, MSRC as JSON; DSA as plain text).</summary>
    Task<string> GetStringAsync(Uri uri, CancellationToken ct);

    /// <summary>GET the resource as a stream (binary feeds, e.g. a hosted wsusscn2.cab mirror).</summary>
    Task<Stream> GetStreamAsync(Uri uri, CancellationToken ct);

    /// <summary>
    /// Conditional GET: send the validators from the stored cursor and let the server decide whether
    /// there is anything to transfer. Returns <see cref="ConditionalFetch.Unchanged"/> on 304.
    ///
    /// <para>This is how a cursor reaches a whole-file feed that offers no filter parameter. It is
    /// not an optimisation detail for <c>usn</c>: that feed's real body is 260&#160;MB, so a run
    /// that can answer "unchanged" without transferring it is the difference between a schedule that
    /// is affordable hourly and one that is not.</para>
    ///
    /// <para>Passing null for both validators degrades to an ordinary GET, which is what the first
    /// run after a fresh install — and any run whose stored cursor predates this contract — does.</para>
    /// </summary>
    Task<ConditionalFetch> GetStringConditionalAsync(
        Uri uri, string? etag, DateTimeOffset? lastModified, CancellationToken ct);
}
