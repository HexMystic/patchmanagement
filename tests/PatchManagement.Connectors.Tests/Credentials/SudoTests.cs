using System.Text;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Tests.Credentials;

/// <summary>
/// Privilege elevation. Review finding M7 is that one <c>ResolvedCredential</c> carries exactly one
/// secret, while an SSH connector doing "<c>sudo</c> for privileged ops" needs two: a login key and
/// a sudo password. Rather than change a frozen contract (NEVER #6), the target carries a second
/// <see cref="EndpointTarget.PrivilegeCredential"/> reference.
///
/// <para><b>The lab cannot test this.</b> <c>labadmin</c> is <c>NOPASSWD:ALL</c> with a locked
/// account password, so the fleet can never demand a sudo password and would report success no
/// matter what this code did. That is exactly why the path is proven here, against a fake session,
/// and why the gap is recorded rather than assumed covered by a green integration run.</para>
/// </summary>
public sealed class SudoTests
{
    private const string SudoPassword = "lab-sudo-secret";

    [Fact]
    public async Task Elevation_with_a_privilege_credential_uses_sudo_dash_S_and_feeds_the_secret_on_stdin()
    {
        var session = new RecordingSshSession();
        var harness = ConnectorHarness.Build(
            session: () => session,
            configureCredentials: c => c.AddSecret(
                ConnectorHarness.SudoCredential, SudoPassword, CredentialKind.WindowsPassword, "labadmin"));

        var result = await harness.Connector.RunAsync(
            ConnectorHarness.Target(withSudo: true),
            new RemoteCommand { CommandLine = "dnf -y upgrade", RequiresElevation = true },
            CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);

        var line = Assert.Single(session.CommandLines);
        Assert.Contains("sudo -S", line);
        Assert.DoesNotContain("sudo -n", line);

        // The secret goes over stdin, never on the command line — a command line is visible in the
        // target's process list to every local user on that host.
        Assert.DoesNotContain(SudoPassword, line);

        var stdin = Assert.Single(session.StdinPayloads);
        Assert.Equal(SudoPassword + "\n", Encoding.UTF8.GetString(stdin));
    }

    [Fact]
    public async Task Elevation_without_a_privilege_credential_falls_back_to_sudo_dash_n()
    {
        var session = new RecordingSshSession();
        var harness = ConnectorHarness.Build(session: () => session);

        await harness.Connector.RunAsync(
            ConnectorHarness.Target(withSudo: false),
            new RemoteCommand { CommandLine = "dnf -y upgrade", RequiresElevation = true },
            CancellationToken.None);

        var line = Assert.Single(session.CommandLines);

        // -n is non-interactive: if the host demands a password sudo fails immediately instead of
        // blocking on a prompt nobody can answer, which is the honest failure (NEVER #5).
        Assert.Contains("sudo -n", line);
        Assert.Empty(Assert.Single(session.StdinPayloads));
    }

    [Fact]
    public async Task A_command_without_elevation_is_not_wrapped_in_sudo_at_all()
    {
        var session = new RecordingSshSession();
        var harness = ConnectorHarness.Build(session: () => session);

        await harness.Connector.RunAsync(
            ConnectorHarness.Target(withSudo: true),
            new RemoteCommand { CommandLine = "cat /etc/os-release", RequiresElevation = false },
            CancellationToken.None);

        var line = Assert.Single(session.CommandLines);
        Assert.Equal("cat /etc/os-release", line);
        Assert.Empty(Assert.Single(session.StdinPayloads));
    }

    [Fact]
    public async Task The_privilege_credential_is_resolved_only_when_elevation_is_actually_requested()
    {
        var harness = ConnectorHarness.Build(
            configureCredentials: c => c.AddSecret(
                ConnectorHarness.SudoCredential, SudoPassword, CredentialKind.WindowsPassword));

        await harness.Connector.RunAsync(
            ConnectorHarness.Target(withSudo: true),
            new RemoteCommand { CommandLine = "uname -a", RequiresElevation = false },
            CancellationToken.None);

        // Resolving a secret that will not be used is a needless decrypt, a needless audit entry,
        // and a needless window in which plaintext exists.
        Assert.Equal(0, harness.Recorder.CountFor(ConnectorHarness.SudoCredential));
        Assert.Equal(1, harness.Recorder.CountFor(ConnectorHarness.LoginCredential));
    }

    [Fact]
    public async Task The_stdin_buffer_carrying_the_sudo_secret_is_zeroed_after_the_command_returns()
    {
        var session = new RecordingSshSession();
        var harness = ConnectorHarness.Build(
            session: () => session,
            configureCredentials: c => c.AddSecret(
                ConnectorHarness.SudoCredential, SudoPassword, CredentialKind.WindowsPassword));

        await harness.Connector.RunAsync(
            ConnectorHarness.Target(withSudo: true),
            new RemoteCommand { CommandLine = "id -u", RequiresElevation = true },
            CancellationToken.None);

        // The session recorded the caller's buffer itself (not a copy). Once the call has returned,
        // the connector must have wiped it: an un-zeroed password sits on the managed heap for the
        // GC's convenience, visible to a memory dump for as long as the process lives.
        var asPassed = Assert.Single(session.StdinBuffersAsPassed);
        Assert.True(
            asPassed.ToArray().All(b => b == 0),
            "The stdin buffer still holds non-zero bytes after RunAsync returned, so the sudo "
            + "secret was left in memory.");
    }
}
