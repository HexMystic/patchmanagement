namespace PatchManagement.Content.Connectors;

/// <summary>
/// Appends incremental query parameters to a feed's endpoint without discarding whatever query it
/// already carries.
///
/// <para><c>content_sources.endpoint</c> is operator-supplied — an air-gapped mirror, a proxy, a
/// pinned API key-less path — and mirrors routinely carry their own query string. Rebuilding the URI
/// from scratch, or concatenating <c>"?"</c> unconditionally, would corrupt those. Null-valued
/// parameters are omitted entirely rather than sent empty, because <c>?after=</c> is a different
/// request from no <c>after</c> at all.</para>
/// </summary>
internal static class FeedUri
{
    public static Uri With(Uri baseUri, params (string Name, string? Value)[] parameters)
    {
        var additions = parameters
            .Where(p => !string.IsNullOrEmpty(p.Value))
            .Select(p => $"{Uri.EscapeDataString(p.Name)}={Uri.EscapeDataString(p.Value!)}")
            .ToArray();

        if (additions.Length == 0)
            return baseUri;

        var builder = new UriBuilder(baseUri);
        var existing = builder.Query.TrimStart('?');

        builder.Query = existing.Length == 0
            ? string.Join('&', additions)
            : existing + "&" + string.Join('&', additions);

        return builder.Uri;
    }
}
