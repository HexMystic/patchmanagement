using System.Text.RegularExpressions;
using PatchManagement.TestSupport;
using PatchManagement.TestSupport.Conventions;

namespace PatchManagement.Discovery.Tests.Sweep;

/// <summary>
/// Pins the Discovery module to a single place where a socket can be opened.
///
/// <para><b>Why this rather than another behavioural test.</b> <see cref="TargetPolicyTests"/>
/// proves the policy stops the sweep. It cannot prove the policy stops <i>the module</i> — a later
/// slice that reaches an endpoint through a second, freshly-written code path would leave every one
/// of those tests green while contacting whatever it liked. The guard against NEVER #4 is not "the
/// sweeper checks the policy"; it is "there is exactly one way out to the network, and the policy
/// sits in front of it".</para>
///
/// <para>Inventory (slice 3) will legitimately reach endpoints — through
/// <c>IEndpointConnector</c>, whose targets come from persisted assets rather than from a typed
/// CIDR. When that lands, this test's allowlist is the place the decision gets recorded, and
/// widening it should require saying why out loud.</para>
/// </summary>
public sealed class SocketChokePointTests
{
    /// <summary>The only file in the module permitted to construct a network client.</summary>
    private static readonly string[] Permitted = ["TcpPortProbe.cs"];

    [Fact]
    public void Only_the_port_probe_opens_a_socket()
    {
        var opensASocket = new Regex(
            @"new\s+(Socket|TcpClient|UdpClient|HttpClient)\s*\(|\.ConnectAsync\s*\(|\.Connect\s*\(",
            RegexOptions.CultureInvariant);

        var hits = SourceScanner.Scan(
            RepoPaths.Source("src", "Modules", "Discovery"),
            opensASocket,
            ignore: (file, _, text) =>
                SourceScanner.IsCommentLine(text)
                || Permitted.Contains(Path.GetFileName(file), StringComparer.Ordinal));

        Assert.True(
            hits.Count == 0,
            "Something in src/Modules/Discovery opens a network connection outside TcpPortProbe, so "
            + "it is not behind DiscoveryTargetPolicy and CLAUDE.md NEVER #4 is not enforced for it. "
            + "Either route it through the probe, or extend this test's allowlist deliberately and "
            + $"record why:{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));

        // Control: the pattern matches the forms it claims to, so a green result means the module is
        // clean rather than the regex being inert — the failure mode HostKeyPolicyTests documents.
        Assert.Matches(opensASocket, "using var client = new TcpClient();");
        Assert.Matches(opensASocket, "await socket.ConnectAsync(address, port, ct);");
        Assert.DoesNotMatch(opensASocket, "var result = await _probe.ProbeAsync(address, port, t, ct);");
    }
}
