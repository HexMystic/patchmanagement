using System.Text;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// Standard input over the REAL transport — the one path the connector's fakes structurally cannot
/// cover.
///
/// <para><b>Why this file exists.</b> The <c>sudo -S</c> elevation path is proven in the unit suite
/// against <c>RecordingSshSession</c>, which records the buffer it is handed and returns. The lab
/// fleet, meanwhile, is <c>NOPASSWD</c> with a locked account password, so no fleet test ever attaches
/// a <see cref="EndpointTarget.PrivilegeCredential"/> and <c>stdin</c> is always empty there. Those two
/// coverage sets are disjoint in precisely the wrong place: <b>no test ever wrote a byte to stdin
/// through SSH.NET</b>, and the code that does so was wrong — it created the input stream before
/// starting execution, which SSH.NET 2025.1.0 rejects outright with
/// <c>InvalidOperationException: The input stream can be used only during execution.</c></para>
///
/// <para>So these start at <c>ISshSession</c> with a real session and no fake in the path.</para>
/// </summary>
[Collection(LabCollection.Name)]
public sealed class SshStdinTests(LabFixture lab)
{
    private static readonly CredentialRef SudoCredential =
        new(Guid.Parse("50d00000-0000-0000-0000-000000000001"));

    private static LabHost Host => LabFleet.All[0];

    /// <summary>
    /// The defect, at its smallest: bytes written to stdin must reach the command.
    ///
    /// <para><c>cat</c> is the whole point — it echoes stdin to stdout, so the assertion is that the
    /// bytes made the round trip, not merely that nothing threw. A test that only asserted "no
    /// exception" would pass against a session that silently discarded stdin.</para>
    /// </summary>
    [Fact]
    public async Task Stdin_reaches_the_remote_command_over_real_sshnet()
    {
        var marker = "PM-STDIN-" + Guid.NewGuid().ToString("N");
        using var session = await lab.OpenRealSessionAsync(Host, CancellationToken.None);

        var result = await session.RunAsync(
            "cat",
            TimeSpan.FromSeconds(30),
            Encoding.UTF8.GetBytes(marker + "\n"),
            CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains(marker, result.StandardOutput, StringComparison.Ordinal);
    }

    /// <summary>
    /// The control for the test above. An empty stdin must still run normally — the fix must not make
    /// the ordinary no-stdin command (every fleet test, and every command a deployment actually runs)
    /// depend on the input-stream path at all.
    /// </summary>
    [Fact]
    public async Task A_command_with_no_stdin_is_unaffected()
    {
        using var session = await lab.OpenRealSessionAsync(Host, CancellationToken.None);

        var result = await session.RunAsync(
            "echo no-stdin-here", TimeSpan.FromSeconds(30), ReadOnlyMemory<byte>.Empty, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        Assert.Contains("no-stdin-here", result.StandardOutput, StringComparison.Ordinal);
    }

    /// <summary>
    /// A larger payload, because a one-line write can succeed on a stream that is closed too early or
    /// never flushed. A key or certificate handed to a command on stdin is the realistic shape.
    /// </summary>
    [Fact]
    public async Task A_multi_kilobyte_stdin_payload_round_trips_intact()
    {
        var payload = string.Concat(Enumerable.Range(0, 400).Select(i => $"line-{i:0000}\n"));
        using var session = await lab.OpenRealSessionAsync(Host, CancellationToken.None);

        var result = await session.RunAsync(
            "cat", TimeSpan.FromSeconds(30), Encoding.UTF8.GetBytes(payload), CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        Assert.Equal(payload.Replace("\r\n", "\n", StringComparison.Ordinal), result.StandardOutput);
    }

    /// <summary>
    /// The whole point, end to end through <c>SshConnector</c>: an elevated command with a privilege
    /// credential attached takes the <c>sudo -S</c> branch and must not throw.
    ///
    /// <para>The lab is <c>NOPASSWD</c>, so <c>sudo</c> never consumes the password — this cannot
    /// prove a password is <em>accepted</em>, and the unit suite's <c>SudoTests</c> still owns the
    /// assertion that the secret goes to stdin rather than the command line. What it proves is the
    /// half no other test could reach: that the transport survives being handed stdin at all. Before
    /// the fix this threw <c>InvalidOperationException</c> straight out of <c>RunAsync</c> — an
    /// untyped exception escaping a connector whose contract is typed results.</para>
    /// </summary>
    [Fact]
    public async Task An_elevated_command_with_a_privilege_credential_runs_over_real_sshnet()
    {
        var credentials = new FakeCredentialProvider();
        credentials.AddLabKey(LabFixture.LabCredential, LabFleet.Username);
        credentials.AddSecret(
            SudoCredential, "unused-because-the-lab-is-nopasswd", CredentialKind.WindowsPassword, LabFleet.Username);

        var connector = lab.ConnectorWith(credentials);
        var target = lab.TargetFor(Host) with { PrivilegeCredential = SudoCredential };

        var result = await connector.RunAsync(
            target,
            new RemoteCommand { CommandLine = "id -u", RequiresElevation = true },
            CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        Assert.Equal("0", result.StandardOutput.Trim());
    }
}
