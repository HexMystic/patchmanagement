using PatchManagement.Content.Abstractions;

namespace PatchManagement.Content.Tests;

/// <summary>
/// A fetcher that serves scripted bodies and — the point of it — <b>records what was asked for</b>.
///
/// <para>Every cursor test in this project asserts through <see cref="Requests"/> or
/// <see cref="Conditionals"/> rather than through the returned batch, because criterion (b) is a
/// claim about the REQUEST. A connector that reads <c>state.Cursor</c>, computes a window and then
/// discards it still produces a correct-looking batch; only the outgoing URI and the outgoing
/// validators can tell the two apart. This is the same standard as CLAUDE.md NEVER #3 — the exit
/// code is a hint, the observed state is the evidence.</para>
///
/// <para>An unscripted request throws rather than returning empty: a connector that fires a request
/// the test did not anticipate must fail loudly, not silently parse nothing and pass.</para>
/// </summary>
internal sealed class FakeContentFetcher(params string[] bodies) : IHttpContentFetcher
{
    private readonly Queue<string> pending = new(bodies);

    /// <summary>Every URI requested, in order — including both legs of a two-request sync.</summary>
    public List<Uri> Requests { get; } = [];

    /// <summary>The validators sent on each conditional GET, in order.</summary>
    public List<ConditionalRequest> Conditionals { get; } = [];

    /// <summary>Validators the next 200 response carries back.</summary>
    public string? ResponseETag { get; set; }

    public DateTimeOffset? ResponseLastModified { get; set; }

    /// <summary>When set, a conditional GET answers 304 and no body is consumed.</summary>
    public bool NotModified { get; set; }

    public Uri LastRequest => Requests.Count > 0
        ? Requests[^1]
        : throw new InvalidOperationException("No request was made.");

    public Task<string> GetStringAsync(Uri uri, CancellationToken ct)
    {
        Requests.Add(uri);
        return Task.FromResult(Next(uri));
    }

    public Task<Stream> GetStreamAsync(Uri uri, CancellationToken ct) =>
        throw new NotSupportedException("No text feed fetches a stream; wsusscn2 reads a local cab.");

    public Task<ConditionalFetch> GetStringConditionalAsync(
        Uri uri, string? etag, DateTimeOffset? lastModified, CancellationToken ct)
    {
        Requests.Add(uri);
        Conditionals.Add(new ConditionalRequest(uri, etag, lastModified));

        return Task.FromResult(NotModified
            ? ConditionalFetch.Unchanged
            : new ConditionalFetch(Next(uri), ResponseETag, ResponseLastModified));
    }

    private string Next(Uri uri) =>
        pending.Count > 0
            ? pending.Dequeue()
            : throw new InvalidOperationException(
                $"The connector requested '{uri}', which this test scripted no body for. An "
                + "unanticipated request is a failure, not an empty read.");

    /// <summary>One conditional GET as the connector issued it.</summary>
    internal sealed record ConditionalRequest(Uri Uri, string? ETag, DateTimeOffset? LastModified);
}
