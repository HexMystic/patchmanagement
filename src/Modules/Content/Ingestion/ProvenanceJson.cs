using System.Text.Json;
using PatchManagement.Content.Model;

namespace PatchManagement.Content.Ingestion;

/// <summary>
/// Serializes provenance entries to the exact jsonb shape the schemas define
/// (camelCase keys, RFC-3339 timestamps, null-valued optionals omitted). The output is ALWAYS a
/// non-empty array when given at least one entry, which is what the DB CHECK
/// (<c>ck_advisories_provenance_non_empty</c> / <c>ck_patches_provenance_non_empty</c>) requires.
/// </summary>
public static class ProvenanceJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Serialize the provenance array. Throws on an empty list — an unattributable
    /// record must never reach the database (DIFFERENTIATORS #4); the caller has a bug if it does.</summary>
    public static string Serialize(IReadOnlyList<ProvenanceEntry> entries)
    {
        if (entries.Count == 0)
            throw new ArgumentException("Provenance must have at least one entry.", nameof(entries));

        return JsonSerializer.Serialize(entries, Options);
    }

    /// <summary>Serialize a single provenance entry (for overlay merges).</summary>
    public static string SerializeOne(ProvenanceEntry entry) =>
        JsonSerializer.Serialize(new[] { entry }, Options);
}
