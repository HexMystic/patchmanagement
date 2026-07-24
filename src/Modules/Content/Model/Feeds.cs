namespace PatchManagement.Content.Model;

/// <summary>
/// The frozen content vocabulary (Phase 1, ADR 0010). These strings are the ONLY legal values for
/// <c>content_sources.kind</c> and for provenance <c>source</c>; the DB CHECK constraints reject
/// anything else. They are surfaced here as named constants so a connector cannot fat-finger a
/// feed name — a typo would otherwise pass compilation and fail with a Postgres <c>23514</c> at
/// ingest time.
/// </summary>
public static class Feeds
{
    /// <summary>NVD — CVE overlay: severity, CVSS. Publishes advisories, not fixes (ADR 0008/0011).</summary>
    public const string Nvd = "nvd";

    /// <summary>CISA KEV — scoring overlay. Enriches an existing advisory; never a publisher.</summary>
    public const string Kev = "kev";

    /// <summary>FIRST EPSS — scoring overlay. Enriches an existing advisory; never a publisher.</summary>
    public const string Epss = "epss";

    /// <summary>Ubuntu Security Notices — advisory + patch (deb).</summary>
    public const string Usn = "usn";

    /// <summary>Red Hat Security Advisories — advisory + patch (rpm). Also serves Rocky/Alma.</summary>
    public const string Rhsa = "rhsa";

    /// <summary>Microsoft Security Response Center — the Windows advisory side (ADR 0008).</summary>
    public const string Msrc = "msrc";

    /// <summary>wsusscn2.cab offline scan catalogue — the Windows applicability/patch side (ADR 0008).</summary>
    public const string Wsusscn2 = "wsusscn2";

    /// <summary>Debian Security Advisories — advisory + patch (deb).</summary>
    public const string Dsa = "dsa";
}
