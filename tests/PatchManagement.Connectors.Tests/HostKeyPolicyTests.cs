using System.Text.RegularExpressions;
using PatchManagement.TestSupport;
using PatchManagement.TestSupport.Conventions;

namespace PatchManagement.Connectors.Tests;

/// <summary>
/// Host-key verification posture.
///
/// <para>The factory used to accept whatever key the far end presented, unconditionally. That
/// authenticates anything able to answer on the target's address and then sends it a private key —
/// for a product whose whole job is privileged remote execution, the wrong default however
/// convenient it is in a lab.</para>
///
/// <para>These two assertions still hold after D-301: the default is still refuse, and trust is
/// still never hardcoded. What the flag MEANS narrowed — it now governs only whether an unpinned
/// endpoint may be pinned on first sight. The comparison that refuses a CHANGED key lives in
/// <c>HostKeyGateTests</c>, and deliberately does not consult this flag at all.</para>
/// </summary>
public sealed class HostKeyPolicyTests
{
    [Fact]
    public void Unknown_host_keys_are_refused_unless_a_deployment_opts_in()
    {
        Assert.False(new ConnectorSecurityOptions().AllowUnknownHostKeys);
    }

    /// <summary>
    /// Guards the default from being quietly reinstated in code. An options flag that nothing reads
    /// is worse than no flag: it reads as a control while the behaviour is unconditional.
    /// </summary>
    [Fact]
    public void No_source_hardcodes_trust_in_a_presented_host_key()
    {
        var hardcoded = new Regex(@"CanTrust\s*=\s*true", RegexOptions.CultureInvariant);

        var hits = SourceScanner.Scan(
            RepoPaths.Source("src", "Modules", "Connectors"),
            hardcoded,
            ignore: (_, _, text) => SourceScanner.IsCommentLine(text));

        Assert.True(
            hits.Count == 0,
            "Host-key trust is hardcoded, so ConnectorSecurityOptions.AllowUnknownHostKeys is "
            + $"decorative and every connection is interceptable:{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));

        // Control: the pattern does match the offending form, so a green result means the code is
        // clean rather than the regex being wrong — the failure mode that made \b-ComputerName inert.
        Assert.Matches(hardcoded, "client.HostKeyReceived += (_, e) => e.CanTrust = true;");
        Assert.DoesNotMatch(hardcoded, "e.CanTrust = _security.AllowUnknownHostKeys;");
    }
}
