namespace PatchManagement.Connectors.Model;

/// <summary>A single installed package as observed on the endpoint (name/version/arch).</summary>
public sealed record InstalledPackage(string Name, string Version, string Architecture);

/// <summary>
/// Basic inventory facts gathered from an endpoint: OS identity and the installed-package set.
/// Deliberately raw/observed — version comparison and applicability live in later phases
/// (HARD-PROBLEMS #2/#3), so this type does no interpretation.
/// </summary>
public sealed record EndpointFacts
{
    /// <summary>Broad family, e.g. <c>debian</c> or <c>rhel</c> (from the package manager present).</summary>
    public required string OsFamily { get; init; }

    /// <summary><c>ID</c> from os-release, e.g. <c>ubuntu</c>, <c>debian</c>, <c>rocky</c>, <c>almalinux</c>.</summary>
    public required string OsId { get; init; }

    /// <summary><c>VERSION_ID</c> from os-release, e.g. <c>22.04</c>, <c>9.3</c>.</summary>
    public required string OsVersion { get; init; }

    public required string Architecture { get; init; }

    /// <summary>The package manager used to enumerate packages: <c>dpkg</c> or <c>rpm</c>.</summary>
    public required string PackageManager { get; init; }

    public required IReadOnlyList<InstalledPackage> Packages { get; init; }
}
