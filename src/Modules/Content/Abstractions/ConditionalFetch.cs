namespace PatchManagement.Content.Abstractions;

/// <summary>
/// The result of a conditional GET: either the body, or the server's positive assertion that
/// nothing changed since the validators we sent.
///
/// <para><b>Why this exists.</b> Four of the eight feeds (<c>kev</c>, <c>epss</c>, <c>usn</c>,
/// <c>dsa</c>) publish a whole file with no server-side filter parameter, so there is no
/// <c>?after=</c> to append. Inventing one would repeat this module's recurring defect — a request
/// written against a shape no server produces (see <c>rhsa</c>, <c>msrc</c> and ADR 0022). HTTP's
/// own validators are the mechanism those hosts actually implement, so that is what a cursor sends
/// to them.</para>
///
/// <para><b>A 304 is evidence, not an empty read.</b> This module treats "parsed nothing" as a
/// format change and throws (ADR 0022 mitigation (a)). <see cref="NotModified"/> is the opposite
/// case: the server was asked and answered that the catalogue is unchanged. The connector holds its
/// cursor and writes no rows, and that is an honest <c>ok</c> — not the "reports success while
/// untrue" hazard, because the absence was asserted rather than inferred from silence.</para>
/// </summary>
/// <param name="Content">The body, or null when the server answered 304.</param>
/// <param name="ETag">The response's <c>ETag</c>, to send back as <c>If-None-Match</c> next run.</param>
/// <param name="LastModified">The response's <c>Last-Modified</c>, for <c>If-Modified-Since</c>.</param>
public sealed record ConditionalFetch(string? Content, string? ETag, DateTimeOffset? LastModified)
{
    /// <summary>True when the server answered 304 and there is nothing to parse.</summary>
    public bool NotModified => Content is null;

    /// <summary>The 304 case. Carries no validators: the stored ones stay valid by definition.</summary>
    public static ConditionalFetch Unchanged { get; } = new(null, null, null);
}
