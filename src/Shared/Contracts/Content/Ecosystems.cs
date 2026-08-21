namespace PatchManagement.Contracts.Content;

/// <summary>
/// The three implemented version-comparator ecosystems (HARD-PROBLEMS #3). CHECK-constrained on
/// <c>advisory_affects.ecosystem</c>; a fourth ecosystem needs a comparator before it needs a row.
/// </summary>
public static class Ecosystems
{
    /// <summary>Debian/Ubuntu — <c>dpkg --compare-versions</c> semantics.</summary>
    public const string Deb = "deb";

    /// <summary>RHEL/Rocky/Alma — <c>rpmvercmp</c> semantics (epoch dominates).</summary>
    public const string Rpm = "rpm";

    /// <summary>Windows — four-part build numbers.</summary>
    public const string Windows = "windows";

    /// <summary>
    /// The generic third-party application ecosystem (ADR 0019). A Chrome MSI or an Adobe PKG is not
    /// a dpkg package, not an rpm and not a Windows build threshold. It names the ECOSYSTEM, not the
    /// vendor — the vendor's product goes in <c>package_name</c>. Phase 16 implements its comparator;
    /// Phase 6 must resolve comparators by ecosystem so adding one is a registration, not a rewrite.
    /// </summary>
    public const string App = "app";
}
