using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Facts;

/// <summary>
/// Pure parsers for the raw text the facts collector reads off a Linux endpoint. Kept separate from
/// the connector so parsing is unit-tested against captured fixtures with no SSH involved. Does no
/// interpretation/version-comparison (that is a later phase — HARD-PROBLEMS #2/#3).
/// </summary>
public static class LinuxFactsParser
{
    /// <summary>Parse the small key=value block emitted by <c>. /etc/os-release; echo "$ID|$VERSION_ID"</c>.</summary>
    public static (string Id, string Version) ParseOsRelease(string output)
    {
        var line = FirstNonEmptyLine(output);
        var parts = line.Split('|');
        var id = parts.Length > 0 ? Unquote(parts[0]) : string.Empty;
        var version = parts.Length > 1 ? Unquote(parts[1]) : string.Empty;
        return (id, version);
    }

    /// <summary>Parse <c>dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'</c> output.</summary>
    public static IReadOnlyList<InstalledPackage> ParseDpkg(string output) =>
        ParseTabbedPackages(output);

    /// <summary>Parse <c>rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'</c> output.</summary>
    public static IReadOnlyList<InstalledPackage> ParseRpm(string output) =>
        ParseTabbedPackages(output);

    private static IReadOnlyList<InstalledPackage> ParseTabbedPackages(string output)
    {
        var packages = new List<InstalledPackage>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim('\r', ' ', '\t');
            if (line.Length == 0) continue;

            var cols = line.Split('\t');
            if (cols.Length < 2) continue;

            var name = cols[0].Trim();
            var version = cols[1].Trim();
            var arch = cols.Length > 2 ? cols[2].Trim() : string.Empty;
            if (name.Length == 0) continue;

            packages.Add(new InstalledPackage(name, version, arch));
        }
        return packages;
    }

    private static string FirstNonEmptyLine(string text)
    {
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim('\r', ' ', '\t');
            if (line.Length > 0) return line;
        }
        return string.Empty;
    }

    private static string Unquote(string value) => value.Trim().Trim('"');
}
