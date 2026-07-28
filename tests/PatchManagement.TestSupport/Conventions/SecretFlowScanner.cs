using System.Text.RegularExpressions;

namespace PatchManagement.TestSupport.Conventions;

/// <summary>
/// Finds secret material reaching a string-materialising call, <b>following it through local
/// variables</b> rather than matching one syntactic form.
///
/// <para><b>This is the SECOND layer, not the guarantee. Cold review R4 demoted it.</b> The primary
/// enforcement for "no secret is ever decoded into a managed string" is
/// <see cref="SecretMaterialisationScanner"/>, which enumerates every call in the module that can
/// make text out of bytes and requires each to be individually justified. This scanner is kept
/// behind it because it covers something the capability check cannot: a secret reaching one of the
/// few calls that ARE justified. Read the residual note below before trusting it for anything
/// else.</para>
///
/// <para><b>Why this is not a regex.</b> The rule it enforces — "no secret is ever decoded into a
/// managed string" — was previously a single pattern anchored on <c>.Secret</c> appearing inside the
/// same statement as the call. Cold review R3 broke it in one line: splitting
/// <c>Encoding.UTF8.GetString(credential.Secret)</c> into <c>var b = credential.Secret.ToArray();</c>
/// followed by <c>Encoding.UTF8.GetString(b);</c> reintroduced the immortal managed string with the
/// whole suite green. A statement-scoped pattern can only ever catch the one shape someone happened
/// to write; the defect is about where the bytes GO, so the check has to follow them.</para>
///
/// <para><b>And it cannot be behavioural.</b> A managed string that exists for a while and is then
/// collected is indistinguishable at runtime from one that never existed — and the obvious proxy does
/// not work either: <see cref="System.Net.NetworkCredential"/> reports a non-null, non-read-only
/// <c>SecurePassword</c> of the same length whichever constructor built it, so asserting on it is
/// green for the defect too. Only the source can say which happened.</para>
///
/// <para><b>It under-reports, and this doc used to deny it.</b> The paragraph here previously argued
/// that per-file taint made the analysis over-approximate — that it "can only report MORE than the
/// truth, whereas an under-report is a guarantee that quietly does not hold". <b>That was false in
/// both directions and the second half was the dangerous half.</b> Taint is seeded from assignments
/// and <c>CopyTo</c> only, so a <b>method parameter is never tainted</b>. Cold review R4 laundered a
/// private key straight past it with one extracted helper —
/// <c>DecodeSecret(byte[] m) => Encoding.UTF8.GetString(m)</c> — and the same hole is open to
/// lambdas, local functions, extension methods, <c>out</c> parameters, instance fields and any
/// cross-file helper, because taint does not cross a file either. A guard whose documentation
/// asserts it cannot fail in the exact way it fails is worse than no guard: it stops the next reader
/// looking. What it genuinely does cover is a secret flowing through <em>straight-line local
/// assignment</em> in one method, which is real but narrow.</para>
///
/// <para><b>It also over-reports, separately.</b> Taint is keyed per FILE, so a name tainted in one
/// method is treated as tainted in every method of that file — an unrelated
/// <c>Convert.ToBase64String(data)</c> is a hit if some other method assigned <c>data</c> from the
/// secret. That direction is harmless on its own (a human reads a failing test), and it is retained
/// deliberately, but it is not what makes the analysis sound. The same reasoning governs
/// <see cref="SourceScanner.StripComments"/>.</para>
/// </summary>
public static class SecretFlowScanner
{
    /// <summary>Calls that turn bytes into a managed <c>string</c> — the thing that cannot be zeroed.</summary>
    private static readonly Regex Sink = new(
        @"(?:Encoding\.\w+\.GetString|Convert\.ToBase64String|BitConverter\.ToString)\s*\(",
        RegexOptions.CultureInvariant);

    /// <summary>An assignment, capturing the assigned name and its right-hand side.</summary>
    private static readonly Regex Assignment = new(
        @"(?:^|[;{}\)]|\bvar\b)\s*(?:var\s+)?([A-Za-z_]\w*)\s*=\s*([^;]*);",
        RegexOptions.Multiline | RegexOptions.CultureInvariant);

    /// <summary>A copy INTO a buffer, which taints the destination rather than the source.</summary>
    private static readonly Regex CopyInto = new(
        @"([^;\n]*?)\.CopyTo\s*\(\s*([A-Za-z_]\w*)",
        RegexOptions.CultureInvariant);

    /// <summary>The root of all taint: the resolved credential's bytes.</summary>
    private static readonly Regex SecretRoot = new(@"\.Secret\b", RegexOptions.CultureInvariant);

    /// <summary>
    /// Every place secret material — directly or through locals — reaches a string-materialising call.
    /// </summary>
    public static IReadOnlyList<SourceScanner.Hit> Scan(string directory)
    {
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException($"Secret-flow scan target not found: '{directory}'.");

        var root = RepoPaths.RepoRoot().FullName;
        var hits = new List<SourceScanner.Hit>();

        foreach (var file in Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories))
        {
            if (IsBuildOutput(file)) continue;

            foreach (var (line, excerpt) in Offences(File.ReadAllText(file)))
                hits.Add(new SourceScanner.Hit(Path.GetRelativePath(root, file), line, excerpt));
        }

        return hits;
    }

    /// <summary>
    /// The offences in one source text, as (line, excerpt). Exposed so the pattern audit can drive the
    /// analysis over known-offending and known-innocent samples — a scan that cannot match its target
    /// passes forever and guards nothing, which this module has shipped twice.
    /// </summary>
    public static IReadOnlyList<(int Line, string Excerpt)> Offences(string source)
    {
        var text = SourceScanner.StripComments(source);
        var tainted = TaintedNames(text);
        var found = new List<(int, string)>();

        foreach (Match match in Sink.Matches(text))
        {
            var arguments = ArgumentsOf(text, match.Index + match.Length - 1);
            if (!CarriesSecret(arguments, tainted)) continue;

            var line = text.Take(match.Index).Count(c => c == '\n') + 1;
            var excerpt = (match.Value + arguments + ")").ReplaceLineEndings(" ").Trim();

            found.Add((line, excerpt.Length > 200 ? excerpt[..200] + "…" : excerpt));
        }

        return found;
    }

    /// <summary>
    /// Local names holding secret material, to a fixpoint — so a value laundered through several
    /// intermediate variables is still tracked.
    /// </summary>
    internal static HashSet<string> TaintedNames(string text)
    {
        var tainted = new HashSet<string>(StringComparer.Ordinal);

        // Iterate to a fixpoint: each pass can taint a name whose source was only tainted last pass.
        // Bounded by the number of assignments, so it always terminates.
        bool changed;
        do
        {
            changed = false;

            foreach (Match assignment in Assignment.Matches(text))
            {
                var name = assignment.Groups[1].Value;
                if (tainted.Contains(name)) continue;
                if (!CarriesSecret(assignment.Groups[2].Value, tainted)) continue;

                tainted.Add(name);
                changed = true;
            }

            foreach (Match copy in CopyInto.Matches(text))
            {
                var destination = copy.Groups[2].Value;
                if (tainted.Contains(destination)) continue;
                if (!CarriesSecret(copy.Groups[1].Value, tainted)) continue;

                tainted.Add(destination);
                changed = true;
            }
        }
        while (changed);

        return tainted;
    }

    /// <summary>Whether an expression names the secret directly or any name already known to hold it.</summary>
    private static bool CarriesSecret(string expression, IReadOnlySet<string> tainted) =>
        SecretRoot.IsMatch(expression)
        || tainted.Any(name => Regex.IsMatch(expression, $@"(?<![\w.]){Regex.Escape(name)}\b", RegexOptions.CultureInvariant));

    /// <summary>
    /// The argument text of a call whose opening parenthesis is at <paramref name="openParen"/>,
    /// matching parentheses so a nested call is included rather than truncating at the first ')'.
    /// </summary>
    private static string ArgumentsOf(string text, int openParen)
    {
        var depth = 0;
        for (var i = openParen; i < text.Length; i++)
        {
            if (text[i] == '(') depth++;
            else if (text[i] == ')' && --depth == 0)
                return text[(openParen + 1)..i];
        }

        return text[(openParen + 1)..];
    }

    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
}
