using System.Text.RegularExpressions;

namespace PatchManagement.TestSupport.Conventions;

/// <summary>
/// Every place connector code can turn bytes or chars into managed text — <b>enumerated, not
/// analysed</b>.
///
/// <para><b>Why this replaces flow analysis as the primary guard.</b> Cold review R4 defeated
/// <see cref="SecretFlowScanner"/> with a one-line helper:
/// <c>DecodeSecret(byte[] m) => Encoding.UTF8.GetString(m)</c>, called with the secret. The scanner
/// tracks locals, so it never taints <c>m</c>, and the whole suite stayed green while a private key
/// sat in an immortal managed string. Lambdas, local functions, extension methods, <c>out</c>
/// parameters, instance fields and cross-file helpers all defeat it the same way. Chasing those
/// shapes with more analysis loses by construction: the attacker picks the shape, and the analysis
/// has to have anticipated it.</para>
///
/// <para><b>So this does not track data at all — it restricts capability.</b> Whatever route the bytes
/// take, laundering them into a string must eventually CALL something that makes text out of them,
/// inside code we own. There are four such calls in the entire connector surface. This scanner finds
/// them all and the test pins each one to an explicit justification; anything new, moved or edited is
/// red by default. A fifth call is a failing test whichever helper, lambda or field fed it — the shape
/// is irrelevant, which is precisely the property flow analysis could not have.</para>
///
/// <para><b>Fail-closed, and that is the whole point.</b> An over-report is a human reading a diff and
/// writing one line of justification. An under-report is a credential guarantee that quietly does not
/// hold. <see cref="SecretFlowScanner"/> was over-approximate in the direction that does not matter
/// (name collisions) and under-approximate in the one that does.</para>
///
/// <para><b>Residual, stated plainly.</b> The capability set below is the BCL surface that converts
/// bytes/chars to text. Three things are outside it: a hand-rolled conversion loop that calls nothing
/// on this list; a serializer reached indirectly (<c>JsonSerializer.Serialize(secretBytes)</c>);
/// and third-party code, which we cannot fix and do not govern — SSH.NET's own key parser is measured
/// to create four managed copies of every private key it reads (docs/HARD-PROBLEMS.md §13). The first
/// two are why <see cref="SecretFlowScanner"/> is retained behind this as a second layer rather than
/// deleted. The third is a documented limit of the guarantee, not a hole in this check.</para>
///
/// <para><b>Runtime observation was tried for the first residual and does not work.</b> R4 built a
/// memory scan that looks for the secret as UTF-16 after an operation. It is red for correct code —
/// third-party parsers pollute it, and <c>SecureString.AppendChar</c> decrypts to append, so even the
/// first-party conversion transiently leaves copies — and it is nondeterministic about it. Details and
/// measurements in docs/HARD-PROBLEMS.md §13.</para>
/// </summary>
public static class SecretMaterialisationScanner
{
    /// <summary>A call that can produce managed text from bytes or chars.</summary>
    public sealed record Site(string RelativePath, int Line, string Call)
    {
        /// <summary>Identity for the allow-list: the file and the call, never the line number.</summary>
        /// <remarks>
        /// Line numbers are deliberately excluded. Pinning them would turn every unrelated edit above
        /// a justified call into a failure, and the fix for that noise is to stop pinning — which is
        /// how allow-lists rot into rubber stamps. The call text is what needs re-reading when it
        /// changes.
        /// </remarks>
        public string Key => $"{RelativePath.Replace('\\', '/')} :: {Call}";
    }

    /// <summary>
    /// The enumerated capability set: BCL calls that materialise managed text from bytes or chars.
    ///
    /// <para><c>Encoding.*.GetBytes</c> is deliberately absent — it runs the safe direction (text to
    /// bytes) and banning it would flag the WinRM script encoder, which never touches a secret.</para>
    /// </summary>
    private static readonly Regex Materialiser = new(
        @"(?:Encoding\.\w+\.GetString"
        + @"|Encoding\.\w+\.GetChars"
        + @"|Convert\.ToBase64String"
        + @"|Convert\.ToHexString"
        + @"|BitConverter\.ToString"
        + @"|string\.Create"
        + @"|Utf8\.ToUtf16"
        + @"|Marshal\.PtrToString\w*"
        + @"|new\s+string)\s*\(",
        RegexOptions.CultureInvariant);

    /// <summary>Every materialising call under <paramref name="directory"/>.</summary>
    public static IReadOnlyList<Site> Sites(string directory)
    {
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException($"Materialisation scan target not found: '{directory}'.");

        var root = RepoPaths.RepoRoot().FullName;
        var sites = new List<Site>();

        foreach (var file in Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories))
        {
            if (IsBuildOutput(file)) continue;

            foreach (var (line, call) in SitesIn(File.ReadAllText(file)))
                sites.Add(new Site(Path.GetRelativePath(root, file), line, call));
        }

        return sites;
    }

    /// <summary>
    /// The materialising calls in one source text, as (line, normalised call). Exposed so the pattern
    /// audit can drive it over known samples — a scan that cannot match its target passes forever.
    /// </summary>
    public static IReadOnlyList<(int Line, string Call)> SitesIn(string source)
    {
        var text = SourceScanner.StripComments(source);
        var found = new List<(int, string)>();

        foreach (Match match in Materialiser.Matches(text))
        {
            var open = match.Index + match.Length - 1;
            var call = match.Value + ArgumentsOf(text, open) + ")";
            var line = text.Take(match.Index).Count(c => c == '\n') + 1;

            found.Add((line, Normalise(call)));
        }

        return found;
    }

    /// <summary>Whitespace-collapsed so reflowing a call across lines does not change its identity.</summary>
    private static string Normalise(string call) =>
        Regex.Replace(call.ReplaceLineEndings(" "), @"\s+", " ").Trim();

    /// <summary>Argument text of the call whose '(' is at <paramref name="openParen"/>, parens matched.</summary>
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
