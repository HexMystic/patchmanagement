using System.Text.Json;
using System.Text.Json.Serialization;
using PatchManagement.Content.Abstractions;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// The restated cursor contract for Phase 5 criterion (b). ADR 0022 named the problem directly —
/// <i>"the cursor contract breaks … the slice must restate the cursor contract, not paper over
/// it"</i> — because one opaque string cannot serve two different incremental mechanisms.
///
/// <para>A cursor now carries up to two things:</para>
/// <list type="bullet">
///   <item><see cref="Semantic"/> — the feed's own bookmark, computed by <c>Parse</c>: an NVD
///     <c>lastModified</c>, a KEV <c>catalogVersion</c>, a full DSA id, a wsusscn2 <c>PackageId</c>.
///     This is what a connector sends as a query parameter, or compares against, and it is what
///     every existing parse test already pins.</item>
///   <item><see cref="ETag"/> / <see cref="LastModified"/> — HTTP validators, for the whole-file
///     feeds whose only server-side incremental mechanism is a conditional GET.</item>
/// </list>
///
/// <para><b>The encoding is deliberately backward compatible.</b> With no validators it formats back
/// to the bare semantic string, byte for byte — so the six feeds that need no conditional GET keep
/// the exact cursor value they persist today, and every row already in <c>content_sources.cursor</c>
/// still reads correctly. Only when validators are present does it become a small JSON object, and
/// <see cref="Read"/> accepts either form. A stored value that is neither (a legacy string that
/// happens to start with <c>{</c>) degrades to semantic-only, which costs one full fetch rather than
/// throwing mid-sync.</para>
///
/// <para>The cursor stays <b>opaque outside the connector that produced it</b>, exactly as
/// <c>NormalizedBatch.Cursor</c> documents. This type is the connectors' shared codec for it, not a
/// public interpretation of it: <c>ContentSyncService</c> still moves it through as a string and
/// never looks inside.</para>
/// </summary>
public sealed record FeedCursor(string? Semantic, string? ETag = null, DateTimeOffset? LastModified = null)
{
    /// <summary>The no-cursor case: a first run, or a feed that never emitted one.</summary>
    public static FeedCursor None { get; } = new((string?)null);

    /// <summary>True when there is a validator worth sending on a conditional GET.</summary>
    public bool HasValidators => !string.IsNullOrWhiteSpace(ETag) || LastModified is not null;

    /// <summary>
    /// Decode a persisted <c>content_sources.cursor</c>. Never throws: an unreadable cursor must
    /// cost a full re-fetch, not a failed sync — the failure path would hold the same unreadable
    /// value and the feed would never recover on its own.
    /// </summary>
    public static FeedCursor Read(string? persisted)
    {
        if (string.IsNullOrWhiteSpace(persisted))
            return None;

        var trimmed = persisted.TrimStart();
        if (trimmed.Length == 0 || trimmed[0] != '{')
            return new FeedCursor(persisted);

        try
        {
            var wire = JsonSerializer.Deserialize<Wire>(persisted);
            return wire is null
                ? new FeedCursor(persisted)
                : new FeedCursor(wire.Semantic, wire.ETag, wire.LastModified);
        }
        catch (JsonException)
        {
            // A bare semantic value that merely looks like JSON. Treat it as what it is.
            return new FeedCursor(persisted);
        }
    }

    /// <summary>
    /// Encode for persistence. Bare string when there are no validators — see the type's note on
    /// backward compatibility — and null when there is nothing at all, so the column stays NULL
    /// rather than gaining a JSON object that means "empty".
    /// </summary>
    public string? Format()
    {
        if (!HasValidators)
            return Semantic;

        return JsonSerializer.Serialize(new Wire
        {
            Semantic = Semantic,
            ETag = ETag,
            LastModified = LastModified,
        });
    }

    /// <summary>
    /// The cursor to persist after a 200: whatever <c>Parse</c> computed, carrying the validators the
    /// response just supplied. A response with no validators yields a bare semantic cursor again,
    /// which is correct — the next run simply cannot make its GET conditional.
    /// </summary>
    public static FeedCursor From(string? semantic, ConditionalFetch fetch) =>
        new(semantic, fetch.ETag, fetch.LastModified);

    /// <summary>
    /// Short property names because this string lands in a database column on every sync of every
    /// feed, and it is never read by a human.
    /// </summary>
    private sealed class Wire
    {
        [JsonPropertyName("c")] public string? Semantic { get; set; }
        [JsonPropertyName("e")] public string? ETag { get; set; }
        [JsonPropertyName("m")] public DateTimeOffset? LastModified { get; set; }
    }
}
