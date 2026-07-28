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
}
