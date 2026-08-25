using System.Net;
using System.Net.Http.Headers;
using PatchManagement.Content.Abstractions;

namespace PatchManagement.Content.Http;

/// <summary>
/// Production <see cref="IHttpContentFetcher"/> — a thin, time-bounded <see cref="HttpClient"/>
/// wrapper. The client's <c>Timeout</c> plus the caller's <see cref="CancellationToken"/> keep every
/// fetch bounded (CLAUDE.md NEVER #5). No credentials are attached: the content feeds are public,
/// and this type must never grow authentication that could be logged (NEVER #1). Tests never use
/// this — they inject a fake fetcher over recorded payloads.
/// </summary>
public sealed class HttpContentFetcher(HttpClient client) : IHttpContentFetcher
{
    public async Task<string> GetStringAsync(Uri uri, CancellationToken ct)
    {
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    public async Task<Stream> GetStreamAsync(Uri uri, CancellationToken ct)
    {
        var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStreamAsync(ct);
    }

    public async Task<ConditionalFetch> GetStringConditionalAsync(
        Uri uri, string? etag, DateTimeOffset? lastModified, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);

        // TryParse, not Parse: the ETag came out of the database, and a stored value that is no
        // longer a well-formed entity tag must degrade to an unconditional GET rather than throw and
        // take the whole sync down. Weak tags (W/"...") are normal for these hosts and parse fine.
        if (!string.IsNullOrWhiteSpace(etag) && EntityTagHeaderValue.TryParse(etag, out var tag))
            request.Headers.IfNoneMatch.Add(tag);

        if (lastModified is { } since)
            request.Headers.IfModifiedSince = since;

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

        if (response.StatusCode == HttpStatusCode.NotModified)
            return ConditionalFetch.Unchanged;

        response.EnsureSuccessStatusCode();

        return new ConditionalFetch(
            await response.Content.ReadAsStringAsync(ct),
            response.Headers.ETag?.ToString(),
            response.Content.Headers.LastModified);
    }
}
