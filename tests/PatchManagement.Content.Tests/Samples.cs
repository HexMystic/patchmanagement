using PatchManagement.TestSupport;

namespace PatchManagement.Content.Tests;

/// <summary>
/// Loads the captured feed payloads under <c>Samples/</c>. See <c>Samples/PROVENANCE.md</c> — every
/// one is a real response from the live feed, and the two hand-written stubs that used to live there
/// were deleted rather than built upon.
///
/// <para>Read from the repo tree via <see cref="RepoPaths"/> rather than copied to the output
/// directory: no csproj in this repo uses <c>CopyToOutputDirectory</c>, and RepoPaths' walk-up to
/// <c>PatchManagement.sln</c> works correctly from a worktree.</para>
/// </summary>
internal static class Samples
{
    /// <summary>
    /// Reads a sample by file name. Throws — never returns empty — so a parse test cannot pass by
    /// parsing nothing. An empty string would make <c>JsonDocument.Parse</c> throw somewhere less
    /// obvious, and a missing-file typo would otherwise look like a parser bug.
    /// </summary>
    public static string Read(string fileName)
    {
        var path = RepoPaths.Source("tests", "PatchManagement.Content.Tests", "Samples", fileName);

        if (!File.Exists(path))
            throw new FileNotFoundException(
                $"Captured feed sample '{fileName}' is missing. Samples are real payloads recorded "
                + "from the live feed (see Samples/PROVENANCE.md) — do NOT hand-write a replacement.",
                path);

        var content = File.ReadAllText(path);

        if (string.IsNullOrWhiteSpace(content))
            throw new InvalidOperationException($"Captured feed sample '{fileName}' is empty: {path}");

        return content;
    }

    /// <summary>One NVD response per captured CVE — each file is one request's whole response.</summary>
    public static string Nvd(string cve) => Read($"nvd.{cve}.json");

    public static string Kev() => Read("kev.sample.json");

    public static string Epss() => Read("epss.sample.json");

    /// <summary>Two complete notices from the 339 MB usn-db map; see PROVENANCE.md.</summary>
    public static string Usn() => Read("usn.sample.json");
}
