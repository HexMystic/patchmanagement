using PatchManagement.Connectors.DoubleHop;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests;

/// <summary>
/// Double-hop detection, and which protocol it applies to.
///
/// <para>HARD-PROBLEMS #9: a WinRM/PS-Remoting session cannot authenticate onward without CredSSP or
/// constrained Kerberos delegation. The connector's job in Phase 3 is to <b>surface</b> that rather
/// than hang. The detector's signals — UNC paths, <c>New-PSSession -ComputerName</c>, <c>net use</c>
/// — are Windows-shaped, and running them against SSH produces false positives on commands that
/// have no second hop at all.</para>
/// </summary>
public sealed class DoubleHopScopeTests
{
    [Theory]
    [InlineData(@"copy \\fileserver\share\patch.msu C:\temp\")]
    [InlineData(@"New-PSSession -ComputerName dc01")]
    [InlineData(@"net use Z: \\fileserver\share")]
    public void Windows_onward_auth_patterns_are_detected_for_WinRm(string commandLine)
    {
        var assessment = DoubleHopDetector.Assess(
            new RemoteCommand { CommandLine = commandLine }, EndpointProtocol.WinRm);

        Assert.True(assessment.RequiresOnwardAuth);
        Assert.False(string.IsNullOrWhiteSpace(assessment.Reason));
    }

    [Theory]
    [InlineData(@"grep -r '\\server\share' /etc")]
    [InlineData(@"echo 'net use' >> /var/log/notes")]
    [InlineData(@"logger 'New-PSSession -ComputerName dc01'")]
    public void Windows_patterns_do_not_fire_against_an_SSH_target(string commandLine)
    {
        // On Linux these are ordinary strings inside ordinary commands. Reporting DoubleHopRequired
        // would refuse to run a command that has no second hop — a false refusal, which for a wave
        // is indistinguishable from a broken estate.
        var assessment = DoubleHopDetector.Assess(
            new RemoteCommand { CommandLine = commandLine }, EndpointProtocol.Ssh);

        Assert.False(assessment.RequiresOnwardAuth);
    }

    [Fact]
    public void An_explicit_caller_hint_is_honoured_on_every_protocol()
    {
        // The caller knows things static inspection cannot. This is protocol-independent because a
        // declared intent to authenticate onward is a fact about the command, not about Windows.
        foreach (var protocol in new[] { EndpointProtocol.Ssh, EndpointProtocol.WinRm })
        {
            var assessment = DoubleHopDetector.Assess(
                new RemoteCommand { CommandLine = "ssh other-host uptime", ExpectsOnwardAuth = true }, protocol);

            Assert.True(assessment.RequiresOnwardAuth, $"hint ignored for {protocol}");
        }
    }

    [Fact]
    public void A_transfer_to_a_UNC_path_is_a_double_hop_on_WinRm()
    {
        // Push and pull were never assessed at all, yet writing to \\server\share over a WinRM
        // session is the textbook double-hop — the case HARD-PROBLEMS #9 opens with.
        var assessment = DoubleHopDetector.Assess(
            new FileTransfer { RemotePath = @"\\fileserver\share\patch.msu" }, EndpointProtocol.WinRm);

        Assert.True(assessment.RequiresOnwardAuth);
    }

    [Fact]
    public void An_ordinary_local_transfer_path_is_not_a_double_hop()
    {
        Assert.False(DoubleHopDetector
            .Assess(new FileTransfer { RemotePath = @"C:\temp\patch.msu" }, EndpointProtocol.WinRm)
            .RequiresOnwardAuth);

        Assert.False(DoubleHopDetector
            .Assess(new FileTransfer { RemotePath = "/tmp/patch.deb" }, EndpointProtocol.Ssh)
            .RequiresOnwardAuth);
    }
}
