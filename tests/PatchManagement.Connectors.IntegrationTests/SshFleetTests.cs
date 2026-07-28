using System.Security.Cryptography;
using System.Text;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// Exit criterion (c): SSH integration passes against all five lab containers — run a command, push
/// and pull a file.
///
/// <para>Every fact is a <c>[Theory]</c> over the real fleet, and the per-distro expectations are
/// what stop this being one test executed five times.</para>
/// </summary>
[Collection(LabCollection.Name)]
public sealed class SshFleetTests(LabFixture lab)
{
    public static TheoryData<LabHost> Fleet => LabFleet.AsTheoryData();

    [Theory, MemberData(nameof(Fleet))]
    public async Task Connectivity_succeeds(LabHost host)
    {
        var result = await lab.Connector.TestConnectivityAsync(lab.TargetFor(host), CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        Assert.True(result.IsReachable);
    }

    [Theory, MemberData(nameof(Fleet))]
    public async Task A_command_runs_and_returns_its_output(LabHost host)
    {
        // A unique marker, so a stale or cached result cannot be mistaken for a fresh one.
        var marker = "PM-" + Guid.NewGuid().ToString("N");

        var result = await lab.Connector.RunAsync(
            lab.TargetFor(host),
            new RemoteCommand { CommandLine = $"echo {marker}" },
            CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains(marker, result.StandardOutput, StringComparison.Ordinal);
    }

    [Theory, MemberData(nameof(Fleet))]
    public async Task A_non_zero_exit_is_reported_honestly_rather_than_thrown(LabHost host)
    {
        var result = await lab.Connector.RunAsync(
            lab.TargetFor(host),
            new RemoteCommand { CommandLine = "sh -c 'echo to-stderr >&2; exit 7'" },
            CancellationToken.None);

        // The command RAN. A non-zero exit is information, not a transport failure — collapsing the
        // two would make a failing patch indistinguishable from an unreachable host, which is the
        // dishonesty the state machine exists to prevent (HARD-PROBLEMS #8).
        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        Assert.Equal(7, result.ExitCode);
        Assert.Contains("to-stderr", result.StandardError, StringComparison.Ordinal);
    }

    [Theory, MemberData(nameof(Fleet))]
    public async Task A_file_round_trips_byte_for_byte(LabHost host)
    {
        var payload = RandomNumberGenerator.GetBytes(64 * 1024);
        var expected = Convert.ToHexString(SHA256.HashData(payload));
        var remotePath = $"/tmp/pm-{Guid.NewGuid():N}.bin";
        var target = lab.TargetFor(host);
        var ct = CancellationToken.None;

        try
        {
            var push = await lab.Connector.PushAsync(
                target, new FileTransfer { RemotePath = remotePath, Content = payload }, ct);

            Assert.Equal(ConnectorOutcome.Ok, push.Outcome);
            Assert.Equal(payload.LongLength, push.BytesTransferred);

            var pull = await lab.Connector.PullAsync(
                target, new FileTransfer { RemotePath = remotePath }, ct);

            Assert.Equal(ConnectorOutcome.Ok, pull.Outcome);
            Assert.NotNull(pull.Content);

            // Hash rather than length: a truncated or re-encoded transfer can preserve the size.
            Assert.Equal(expected, Convert.ToHexString(SHA256.HashData(pull.Content!.Value.ToArray())));
        }
        finally
        {
            await lab.Connector.RunAsync(
                target, new RemoteCommand { CommandLine = $"rm -f {remotePath}" }, ct);
        }
    }

    [Theory, MemberData(nameof(Fleet))]
    public async Task Pushing_the_same_payload_twice_is_safe(LabHost host)
    {
        // CLAUDE.md NEVER #5 says every operation is safe to retry. A caller that times out and
        // retries must not corrupt the target, and until now that was an assertion in a doc.
        var payload = "idempotent-payload"u8.ToArray();
        var remotePath = $"/tmp/pm-{Guid.NewGuid():N}.txt";
        var target = lab.TargetFor(host);
        var ct = CancellationToken.None;
        var transfer = new FileTransfer
        {
            RemotePath = remotePath,
            Content = payload,
            IdempotencyKey = "push:" + remotePath,
        };

        try
        {
            var first = await lab.Connector.PushAsync(target, transfer, ct);
            var second = await lab.Connector.PushAsync(target, transfer, ct);

            Assert.Equal(ConnectorOutcome.Ok, first.Outcome);
            Assert.Equal(ConnectorOutcome.Ok, second.Outcome);

            var check = await lab.Connector.RunAsync(
                target, new RemoteCommand { CommandLine = $"wc -c < {remotePath}" }, ct);

            Assert.Equal(payload.Length, int.Parse(check.StandardOutput.Trim()));
        }
        finally
        {
            await lab.Connector.RunAsync(
                target, new RemoteCommand { CommandLine = $"rm -f {remotePath}" }, ct);
        }
    }

    [Theory, MemberData(nameof(Fleet))]
    public async Task An_elevated_command_runs_as_root(LabHost host)
    {
        // The lab grants NOPASSWD sudo, so this exercises the `sudo -n` path only. The sudo -S
        // password path CANNOT be reached here — labadmin's password is locked — and is proven
        // against a fake session in the unit suite instead. Stated so a green run here is not
        // mistaken for coverage of both.
        var result = await lab.Connector.RunAsync(
            lab.TargetFor(host),
            new RemoteCommand { CommandLine = "id -u", RequiresElevation = true },
            CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        Assert.Equal("0", result.StandardOutput.Trim());
    }

    [Theory, MemberData(nameof(Fleet))]
    public async Task The_endpoint_identifies_itself_as_the_expected_distribution(LabHost host)
    {
        var ct = CancellationToken.None;
        var target = lab.TargetFor(host);

        var osRelease = await lab.Connector.RunAsync(
            target, new RemoteCommand { CommandLine = "cat /etc/os-release" }, ct);
        Assert.Equal(ConnectorOutcome.Ok, osRelease.Outcome);
        // RHEL-family images quote the value (ID=\"rocky\") while Debian-family do not (ID=ubuntu),
        // so the quotes are optional here rather than assumed either way.
        Assert.Matches($"ID=\"?{host.OsIdPrefix}\"?", osRelease.StandardOutput);

        // The package manager is what Phase 4's inventory and Phase 6's comparator will branch on,
        // so each distro is checked for the one it actually ships.
        var manager = await lab.Connector.RunAsync(
            target,
            new RemoteCommand { CommandLine = $"command -v {host.PackageManager} >/dev/null && echo present" },
            ct);
        Assert.Contains("present", manager.StandardOutput, StringComparison.Ordinal);
    }

    [Theory, MemberData(nameof(Fleet))]
    public async Task A_wrong_key_maps_to_auth_failed_not_unreachable(LabHost host)
    {
        // A throwaway key the fleet has never seen. The distinction matters operationally: an
        // unreachable host is a network problem, a rejected key is a credential problem, and an
        // estate report that confuses them sends people to the wrong team.
        using var stray = new SshKeyScratch();
        var provider = new TestSupport.Credentials.FakeCredentialProvider();
        var strayRef = new Contracts.Credentials.CredentialRef(Guid.NewGuid());
        provider.Add(strayRef, stray.PrivateKeyBytes, Contracts.Credentials.CredentialKind.SshKey, LabFleet.Username);

        // DEFAULT budgets — no crutch. This is the configuration that misreported at HEAD.
        var connector = lab.ConnectorWith(provider);
        var target = lab.TargetFor(host) with { Credential = strayRef };

        var result = await connector.TestConnectivityAsync(target, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.AuthFailed, result.Outcome);
    }

    /// <summary>
    /// The other half of the split: an unreachable host is judged on the SHORT budget, so it is
    /// reported quickly rather than after the authentication allowance has drained.
    ///
    /// <para>This is what makes the split pay for itself at scale. Connection concurrency is the
    /// 10,000-endpoint wall (CLAUDE.md §2), and a sweep across a dead subnet holds a connection slot
    /// per host for however long the probe takes. Judging reachability separately means that cost is
    /// the reachability budget, not the authentication one.</para>
    /// </summary>
    [Fact]
    public async Task An_unreachable_host_is_reported_without_spending_the_authentication_budget()
    {
        var target = lab.TargetFor(LabFleet.All[0]) with { Port = 2299 };
        var authenticationBudget = TimeSpan.FromSeconds(45);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await lab.Connector.TestConnectivityAsync(target, CancellationToken.None);
        sw.Stop();

        Assert.Equal(ConnectorOutcome.Unreachable, result.Outcome);
        Assert.True(
            sw.Elapsed < authenticationBudget,
            $"an unreachable host took {sw.Elapsed.TotalSeconds:0.#}s, which means reachability is "
            + "still being judged on the authentication budget rather than its own.");
    }

    [Fact]
    public async Task A_closed_port_maps_to_unreachable()
    {
        // 2299 is outside the published fleet range, so nothing is listening.
        var target = lab.TargetFor(LabFleet.All[0]) with { Port = 2299 };

        var result = await lab.Connector.TestConnectivityAsync(target, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Unreachable, result.Outcome);
    }
}
