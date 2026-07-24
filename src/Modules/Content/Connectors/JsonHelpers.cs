using System.Globalization;
using System.Text.Json;

namespace PatchManagement.Content.Connectors;

/// <summary>
/// Small, defensive accessors over <see cref="JsonElement"/>. Feeds omit fields routinely, so every
/// read tolerates absence and returns null rather than throwing — a connector must degrade to
/// "unknown"/"no fix yet" honestly, never crash the whole sync on one sparse record.
/// </summary>
internal static class JsonHelpers
{
    public static string? StringOrNull(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object
        && e.TryGetProperty(name, out var v)
        && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    public static double? DoubleOrNull(this JsonElement e, string name)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v))
            return null;
        return v.ValueKind switch
        {
            JsonValueKind.Number => v.GetDouble(),
            JsonValueKind.String when double.TryParse(
                v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) => d,
            _ => null,
        };
    }

    public static bool? BoolOrNull(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
            ? v.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => null,
            }
            : null;

    public static DateTimeOffset? DateTimeOffsetOrNull(this JsonElement e, string name)
    {
        var s = e.StringOrNull(name);
        if (s is null)
            return null;
        return DateTimeOffset.TryParse(
            s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var dto)
            ? dto
            : null;
    }

    public static DateOnly? DateOnlyOrNull(this JsonElement e, string name)
    {
        var s = e.StringOrNull(name);
        if (s is null)
            return null;
        return DateOnly.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
            ? d
            : null;
    }

    public static JsonElement? Prop(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : null;

    /// <summary>Enumerate an array property, or nothing if it is absent/not an array.</summary>
    public static IEnumerable<JsonElement> Array(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object
        && e.TryGetProperty(name, out var v)
        && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray()
            : [];
}
