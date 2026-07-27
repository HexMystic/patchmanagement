namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// One container in the dev lab. <see cref="OsFamily"/> and <see cref="PackageManager"/> are what
/// make five containers five different tests rather than the same test run five times — without
/// per-distro expectations the fleet proves only that SSH works somewhere.
/// </summary>
public sealed record LabHost(string Name, int Port, string OsIdPrefix, string OsFamily, string PackageManager)
{
    public override string ToString() => $"{Name}:{Port}";
}

/// <summary>
/// The fleet, as published by <c>lab/docker-compose.yml</c>.
///
/// <para>This duplicates a table that also lives in <c>scripts/verify-env.ps1</c>, which is the only
/// other place the ports are written down. Duplication that nothing checks silently forks, so
/// <c>LabFleetManifestTests</c> asserts the two agree.</para>
/// </summary>
public static class LabFleet
{
    public static readonly IReadOnlyList<LabHost> All =
    [
        new("ubuntu2204", 2201, "ubuntu", "debian", "dpkg"),
        new("ubuntu2404", 2202, "ubuntu", "debian", "dpkg"),
        new("debian12", 2203, "debian", "debian", "dpkg"),
        new("rocky9", 2204, "rocky", "rhel", "rpm"),
        new("alma9", 2205, "almalinux", "rhel", "rpm"),
    ];

    /// <summary>The login every container provisions, with NOPASSWD sudo and a locked password.</summary>
    public const string Username = "labadmin";

    public static TheoryData<LabHost> AsTheoryData()
    {
        var data = new TheoryData<LabHost>();
        foreach (var host in All) data.Add(host);
        return data;
    }
}
