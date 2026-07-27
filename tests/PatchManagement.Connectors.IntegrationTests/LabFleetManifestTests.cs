using System.Text.RegularExpressions;
using PatchManagement.TestSupport;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// Keeps the fleet table honest against the two places it is really defined.
///
/// <para>The ports live in <c>lab/docker-compose.yml</c> and are duplicated in
/// <c>scripts/verify-env.ps1</c>; this suite adds a third copy. Duplication that nothing checks
/// forks silently, and the failure mode is nasty: a renumbered container makes the fleet tests probe
/// a port nobody serves, which reads as "the lab is down" rather than "the table is stale".</para>
/// </summary>
public sealed class LabFleetManifestTests
{
    [Fact]
    public void The_fleet_table_matches_the_compose_file()
    {
        var compose = File.ReadAllText(RepoPaths.Source("lab", "docker-compose.yml"));

        foreach (var host in LabFleet.All)
        {
            // Published as "<hostPort>:22" in the ports list.
            Assert.Matches(new Regex($@"""?{host.Port}:22""?"), compose);
            Assert.Contains(host.Name, compose, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_fleet_table_matches_the_environment_verification_script()
    {
        var script = File.ReadAllText(RepoPaths.Source("scripts", "verify-env.ps1"));

        var declared = Regex.Matches(script, @"Name='(?<name>[^']+)';\s*Port=(?<port>\d+)")
            .Select(m => (Name: m.Groups["name"].Value, Port: int.Parse(m.Groups["port"].Value)))
            .OrderBy(x => x.Port)
            .ToList();

        Assert.True(declared.Count > 0, "no fleet entries were parsed from verify-env.ps1 — the format changed");

        Assert.Equal(
            LabFleet.All.OrderBy(h => h.Port).Select(h => (h.Name, h.Port)).ToList(),
            declared);
    }
}
