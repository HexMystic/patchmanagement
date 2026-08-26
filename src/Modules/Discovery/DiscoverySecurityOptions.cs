namespace PatchManagement.Discovery;

/// <summary>
/// Which addresses this deployment is permitted to sweep. Bound to configuration section
/// <c>Discovery:Security</c>.
///
/// <para><b>Why an in-product guard exists at all.</b> CLAUDE.md NEVER #4 forbids targeting a
/// non-lab machine from a dev session, and until now that rule was enforced entirely by
/// <c>.claude/hooks/lab_only_guard.py</c>, which inspects Bash <c>ssh</c>/<c>scp</c>/<c>sftp</c>
/// command strings. Every endpoint this product reached before Phase 4 was reached along a path
/// that hook could observe. <b>A sweep is not.</b> It opens sockets from our own process, to
/// addresses derived from a CIDR an operator typed, and no hook that reads shell commands can see
/// one of them. The guard therefore has to live in the product, or NEVER #4 simply stops being
/// enforced at exactly the feature that most needs it.</para>
///
/// <para><b>Defaulted closed, in the same shape as
/// <c>ConnectorSecurityOptions.AllowUnknownHostKeys</c>.</b> An empty <see cref="AllowedTargets"/>
/// permits nothing, so a deployment that has not consciously declared its scope sweeps nothing
/// rather than sweeping everything. The dev lab opts in to loopback only. As with the host-key
/// flag, the gating is the point rather than a side effect of an unfinished feature.</para>
///
/// <para><b>It is not dev-only scaffolding, and should not be removed when the lab is.</b> In
/// production this is the blast radius of discovery: the declared ranges are the only addresses the
/// platform will ever contact unbidden. A customer who has been told "we sweep 10.20.0.0/16" has
/// been given a promise, and this is where that promise is kept.</para>
/// </summary>
public sealed class DiscoverySecurityOptions
{
    public const string SectionName = "Discovery:Security";

    /// <summary>
    /// CIDR blocks (or bare addresses) this deployment may sweep. <b>Empty by default, which
    /// permits nothing.</b>
    ///
    /// <para>A requested range must be <i>entirely</i> contained by one of these entries. Partial
    /// overlap is refused rather than clipped to the permitted portion: an operator who asked for
    /// <c>10.0.0.0/16</c> and silently received a sweep of <c>10.0.1.0/24</c> would be told their
    /// estate contains what one subnet of it contains, and would have no way to tell that from the
    /// truth.</para>
    /// </summary>
    public IList<string> AllowedTargets { get; set; } = [];
}
