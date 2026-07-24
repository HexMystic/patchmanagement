namespace PatchManagement.Content.Connectors;

/// <summary>
/// Maps distro release CODENAMES (how Ubuntu/Debian feeds label a release) to the
/// <c>vendor:version</c> platform label the catalogue uses ('ubuntu:22.04', 'debian:12'). This is a
/// label mapping only — the <c>fixed_version</c> string is never touched (ADR 0011). An unknown
/// codename falls back to <c>vendor:codename</c> raw rather than being dropped or fabricated, so a
/// newly-released series still ingests and Phase 6 can map it later.
/// </summary>
internal static class DistroReleases
{
    private static readonly Dictionary<string, string> Ubuntu = new(StringComparer.OrdinalIgnoreCase)
    {
        ["trusty"] = "14.04",
        ["xenial"] = "16.04",
        ["bionic"] = "18.04",
        ["focal"] = "20.04",
        ["jammy"] = "22.04",
        ["kinetic"] = "22.10",
        ["lunar"] = "23.04",
        ["mantic"] = "23.10",
        ["noble"] = "24.04",
        ["oracular"] = "24.10",
    };

    private static readonly Dictionary<string, string> Debian = new(StringComparer.OrdinalIgnoreCase)
    {
        ["stretch"] = "9",
        ["buster"] = "10",
        ["bullseye"] = "11",
        ["bookworm"] = "12",
        ["trixie"] = "13",
    };

    public static string UbuntuPlatform(string codename) =>
        Ubuntu.TryGetValue(codename, out var version) ? $"ubuntu:{version}" : $"ubuntu:{codename}";

    public static string DebianPlatform(string codename) =>
        Debian.TryGetValue(codename, out var version) ? $"debian:{version}" : $"debian:{codename}";
}
