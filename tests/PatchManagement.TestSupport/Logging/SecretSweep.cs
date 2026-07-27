using System.Text;

namespace PatchManagement.TestSupport.Logging;

/// <summary>
/// Scans a body of captured text for a secret in every encoding a logging pipeline might
/// render it in. A sink that formats <c>byte[]</c> with <c>string.Format</c> shows
/// "System.Byte[]", but a JSON or OTel exporter base64s it and a hex dump shows it raw — so
/// checking the UTF-8 form alone proves almost nothing.
///
/// Returns a result rather than asserting, so this assembly needs no test framework.
/// </summary>
public static class SecretSweep
{
    /// <summary>Which encodings of <paramref name="secret"/> appear in <paramref name="body"/>.</summary>
    public static SweepResult Scan(ReadOnlySpan<byte> secret, string body)
    {
        var bytes = secret.ToArray();
        var hits = new List<string>();

        void Check(string encoding, string rendered)
        {
            if (rendered.Length > 0 && body.Contains(rendered, StringComparison.Ordinal))
                hits.Add(encoding);
        }

        Check("utf8", Encoding.UTF8.GetString(bytes));
        Check("base64", Convert.ToBase64String(bytes));
        Check("hex-upper", Convert.ToHexString(bytes));
        Check("hex-lower", Convert.ToHexString(bytes).ToLowerInvariant());

        return new SweepResult(hits);
    }

    /// <inheritdoc cref="Scan(ReadOnlySpan{byte}, string)"/>
    public static SweepResult Scan(string secret, string body) =>
        Scan(Encoding.UTF8.GetBytes(secret), body);
}

/// <summary>
/// The encodings in which a secret was found. <see cref="Leaked"/> false is the passing case.
/// <see cref="Describe"/> exists so a failing assertion names <em>which</em> channel leaked —
/// "found in base64" points at a structured sink, "found in utf8" at a formatted message.
/// </summary>
public sealed record SweepResult(IReadOnlyList<string> Encodings)
{
    public bool Leaked => Encodings.Count > 0;

    public string Describe() =>
        Leaked ? $"secret rendered as: {string.Join(", ", Encodings)}" : "no secret material found";
}
