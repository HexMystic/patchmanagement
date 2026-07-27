using System.Text.RegularExpressions;

namespace PatchManagement.TestSupport.Conventions;

/// <summary>
/// Scans C# source under a directory for a pattern. Used by convention tests that enforce rules the
/// compiler cannot — "this module never calls BeginScope", "no exception message is built from
/// remote output" — where the rule is about what the source is <em>allowed to say</em>.
///
/// <para>Build output is skipped: <c>bin</c>/<c>obj</c> contain generated and copied sources, and a
/// scan that walked them would report the same violation several times and could pass or fail
/// depending on whether someone had built recently.</para>
/// </summary>
public static class SourceScanner
{
    /// <summary>A matching line: repository-relative path, 1-based line number, trimmed text.</summary>
    public sealed record Hit(string RelativePath, int Line, string Text)
    {
        public override string ToString() => $"{RelativePath}:{Line}: {Text}";
    }

    /// <summary>
    /// Every line under <paramref name="directory"/> matching <paramref name="pattern"/>.
    /// Throws when the directory is absent rather than returning zero hits — a convention test that
    /// silently passes because it scanned nothing is worse than no test at all, and a mistyped or
    /// moved path is exactly how that happens.
    /// </summary>
    public static IReadOnlyList<Hit> Scan(string directory, Regex pattern, Func<string, int, string, bool>? ignore = null)
    {
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException($"Convention scan target not found: '{directory}'.");

        var root = RepoPaths.RepoRoot().FullName;
        var hits = new List<Hit>();

        foreach (var file in Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories))
        {
            if (IsBuildOutput(file)) continue;

            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                if (!pattern.IsMatch(lines[i])) continue;
                if (ignore is not null && ignore(file, i + 1, lines[i])) continue;

                hits.Add(new Hit(Path.GetRelativePath(root, file), i + 1, lines[i].Trim()));
            }
        }

        return hits;
    }

    /// <summary>Count of <c>.cs</c> files a scan would consider — a control against scanning nothing.</summary>
    public static int FileCount(string directory) =>
        Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories).Count(f => !IsBuildOutput(f))
            : 0;

    /// <summary>
    /// A comment line, including XML doc and block-comment continuations.
    ///
    /// <para>Most convention scans want this as their <c>ignore</c> predicate. The rules they enforce
    /// are about what the code DOES, and a comment explaining why a bad pattern was removed is not a
    /// reinstatement of it — flagging the explanation just teaches people to delete the explanation.
    /// Both scans in this repo hit exactly that false positive before adopting it.</para>
    /// </summary>
    public static bool IsCommentLine(string line)
    {
        var trimmed = line.TrimStart();
        return trimmed.StartsWith("//", StringComparison.Ordinal)
               || trimmed.StartsWith("*", StringComparison.Ordinal)
               || trimmed.StartsWith("/*", StringComparison.Ordinal);
    }

    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
}
