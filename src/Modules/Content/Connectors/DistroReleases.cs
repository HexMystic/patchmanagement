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
    /// <summary>
    /// Every Ubuntu series, transcribed from Ubuntu's own published list
    /// (<c>https://ubuntu.com/security/releases.json</c>) rather than recalled — 45 entries,
    /// newest first.
    ///
    /// <para>This map previously stopped at <c>oracular</c> (24.10) and held ten entries. It was
    /// missing <b>26.04 LTS</b> and 34 other series, including <c>disco</c>/<c>eoan</c>/<c>impish</c>
    /// which the usn-db still ships notices for. The fallback meant nothing was dropped, but the
    /// current LTS was being labelled <c>ubuntu:resolute</c> instead of <c>ubuntu:26.04</c> — off the
    /// <c>ubuntu:&lt;version&gt;</c> convention Phase 6 matches assets on.</para>
    ///
    /// <para><b>Keep this current.</b> <c>advisory_affects</c> is unique on
    /// <c>(advisory_id, package_name, ecosystem, platform)</c>, so the label is part of row identity:
    /// once content has been ingested, correcting a codename here makes the next sync INSERT a second
    /// row rather than update the first. Adding a series before its first advisory lands is free;
    /// afterwards it is a data migration.</para>
    /// </summary>
    private static readonly Dictionary<string, string> Ubuntu = new(StringComparer.OrdinalIgnoreCase)
    {
        ["stonking"] = "26.10",
        ["resolute"] = "26.04",
        ["questing"] = "25.10",
        ["plucky"] = "25.04",
        ["oracular"] = "24.10",
        ["noble"] = "24.04",
        ["mantic"] = "23.10",
        ["lunar"] = "23.04",
        ["kinetic"] = "22.10",
        ["jammy"] = "22.04",
        ["impish"] = "21.10",
        ["hirsute"] = "21.04",
        ["groovy"] = "20.10",
        ["focal"] = "20.04",
        ["eoan"] = "19.10",
        ["disco"] = "19.04",
        ["cosmic"] = "18.10",
        ["bionic"] = "18.04",
        ["artful"] = "17.10",
        ["zesty"] = "17.04",
        ["yakkety"] = "16.10",
        ["xenial"] = "16.04",
        ["wily"] = "15.10",
        ["vivid"] = "15.04",
        ["utopic"] = "14.10",
        ["trusty"] = "14.04",
        ["saucy"] = "13.10",
        ["raring"] = "13.04",
        ["quantal"] = "12.10",
        ["precise"] = "12.04",
        ["oneiric"] = "11.10",
        ["natty"] = "11.04",
        ["maverick"] = "10.10",
        ["lucid"] = "10.04",
        ["karmic"] = "9.10",
        ["jaunty"] = "9.04",
        ["intrepid"] = "8.10",
        ["hardy"] = "8.04",
        ["gutsy"] = "7.10",
        ["feisty"] = "7.04",
        ["edgy"] = "6.10",
        ["dapper"] = "6.06",
        ["breezy"] = "5.10",
        ["hoary"] = "5.04",
        ["warty"] = "4.10",
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
