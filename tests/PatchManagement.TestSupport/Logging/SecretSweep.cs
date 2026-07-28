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
        Check("hex-upper", Convert.ToHexString(bytes));
        Check("hex-lower", Convert.ToHexString(bytes).ToLowerInvariant());

        // Decimal, comma-separated. NOT a theoretical encoding: Microsoft.Extensions.Logging's
        // message formatter renders an IEnumerable argument by joining its elements, so a byte[]
        // passed to LogInformation("{Key}", buffer) appears as "78, 69, 86, ...". It is the default
        // behaviour of the most obvious way to log a byte array, it does not look like a leak in the
        // source, and none of the encodings above find it.
        Check("decimal-csv", string.Join(", ", bytes));
        Check("decimal-csv-tight", string.Join(",", bytes));

        // Base64 needs alignment variants, and the reason is not academic: a mutation that logged a
        // secret with ONE trailing newline slipped past a naive Convert.ToBase64String(secret)
        // comparison. base64 encodes in 3-byte groups, so a secret embedded at a non-multiple-of-3
        // offset — or followed by more bytes — produces a completely different character sequence
        // that shares no usable substring with the standalone encoding. Checking only the exact
        // encoding of the exact bytes finds a leak solely when the secret was logged entirely alone,
        // which is the one case a careless implementation is least likely to produce.
        foreach (var (label, needle) in Base64Cores(bytes))
            Check(label, needle);

        return new SweepResult(hits);
    }

    /// <summary>
    /// Base64 "cores" for the secret at each of the three byte alignments, with the boundary groups
    /// trimmed off. Whatever surrounds the secret, one of these must appear verbatim if the bytes
    /// were base64-encoded anywhere in the body.
    /// </summary>
    private static IEnumerable<(string Label, string Needle)> Base64Cores(byte[] secret)
    {
        // Below this the trimmed core stops being specific enough to be evidence.
        if (secret.Length < 12) yield break;

        for (var shift = 0; shift < 3; shift++)
        {
            var aligned = new byte[shift + secret.Length];
            secret.CopyTo(aligned, shift);

            var encoded = Convert.ToBase64String(aligned).TrimEnd('=');

            // Drop the leading group carrying the synthetic prefix and the trailing group, which may
            // be partial or fused with whatever follows the secret in the real body.
            if (encoded.Length <= 8) continue;
            yield return ($"base64(align {shift})", encoded[4..^4]);
        }
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
