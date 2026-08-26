using System.Text.RegularExpressions;
using PatchManagement.TestSupport;

namespace PatchManagement.Discovery.IntegrationTests;

/// <summary>
/// The fleet's published host ports, read from <c>lab/docker-compose.yml</c> at test time.
///
/// <para><b>Read rather than hardcoded, and that is the point of criterion (a).</b> The claim being
/// proven is "the sweep finds the real lab and the open ports match the real bindings". A copy of
/// the port table in this file would let the test agree with itself while disagreeing with the
/// fleet — the assertion would survive someone changing a published port, which is exactly the
/// change it should catch. <c>LabFleet</c> already keeps one such copy and needs
/// <c>LabFleetManifestTests</c> to stop it forking from <c>verify-env.ps1</c>; a third copy would
/// need a third reconciliation.</para>
///
/// <para><b>An empty parse is a hard failure, never an empty expectation.</b> A regex that silently
/// matched nothing would leave the sweep asserted against an empty port set, which passes for the
/// wrong reason — the same shape as Phase 5's connectors returning an empty batch with a green
/// status. <see cref="All"/> throws instead.</para>
/// </summary>
internal static class LabPublishedPorts
{
    /// <summary>The five distros the lab publishes (docs/phases/phase-4.md, lab/docker-compose.yml).</summary>
    private const int ExpectedCount = 5;

    /// <summary>Host ports forwarded to a container's SSH port, ascending.</summary>
    public static IReadOnlyList<int> All { get; } = Parse();

    private static IReadOnlyList<int> Parse()
    {
        var compose = Path.Combine(RepoPaths.RepoRoot().FullName, "lab", "docker-compose.yml");

        if (!File.Exists(compose))
        {
            throw new InvalidOperationException(
                $"Cannot read the lab's published ports: '{compose}' is missing. This test derives "
                + "its expectations from the compose file rather than hardcoding them.");
        }

        // Matches the published-port short syntax, e.g.   - "2201:22"
        var published = new Regex(
            @"^\s*-\s*""(?<host>\d{1,5}):(?<container>\d{1,5})""\s*$",
            RegexOptions.CultureInvariant | RegexOptions.Multiline);

        var ports = published
            .Matches(File.ReadAllText(compose))
            .Where(m => m.Groups["container"].Value == "22")
            .Select(m => int.Parse(m.Groups["host"].Value))
            .Distinct()
            .Order()
            .ToList();

        if (ports.Count != ExpectedCount)
        {
            throw new InvalidOperationException(
                $"Expected {ExpectedCount} SSH ports published by '{compose}', found {ports.Count} "
                + $"[{string.Join(", ", ports)}]. Either the fleet changed — in which case this "
                + "count and docs/phases/phase-4.md both need updating deliberately — or the parse "
                + "broke, and an empty expectation set would have made the sweep test pass for the "
                + "wrong reason.");
        }

        return ports;
    }
}
