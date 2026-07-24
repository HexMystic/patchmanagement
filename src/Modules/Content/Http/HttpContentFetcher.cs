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
}
