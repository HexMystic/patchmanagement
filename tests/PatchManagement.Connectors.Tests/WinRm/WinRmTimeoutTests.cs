using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using PatchManagement.Connectors;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Connectors.WinRm;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests.WinRm;

/// <summary>
/// The WinRM connector's own time bounds.
///
/// <para><b>Cold review R2 findings #8 and #9.</b> <c>WinRmConnector</c>'s summary claims it is
/// "structurally identical to <c>SshConnector</c>", and on the two properties NEVER #5 actually cares
/// about it was not: the connectivity probe used a compiled-in 15 seconds rather than
/// <see cref="ConnectorTimeoutOptions"/>, and no operation carried a deadline of its own — it handed
/// its budget to <see cref="IWinRmClient"/> and trusted it. The shipped client does bound itself, but
/// the interface is a seam and the WinRM path has never run against a real host (D-303), so
/// "the transport handles it" is an assumption rather than a guarantee.</para>
///
/// <para>A stalling client stands in for an implementation that ignores its budget — which is exactly
/// the case the connector-level deadline exists to survive.</para>
/// </summary>
public sealed class WinRmTimeoutTests
{
    [Fact(Timeout = 30000)]
    public async Task A_command_is_bounded_by_the_connector_even_when_the_client_ignores_its_budget()
    {
        var time = new FakeTimeProvider();
        var client = new StallingWinRmClient();
        var connector = Build(client, time);

        var running = connector.RunAsync(
            Target(),
            new RemoteCommand { CommandLine = "whoami", Timeout = TimeSpan.FromSeconds(30) },
            CancellationToken.None);

        await client.Entered;
        time.Advance(TimeSpan.FromSeconds(31));

        var result = await Settled(running, "the command");
        Assert.Equal(ConnectorOutcome.Timeout, result.Outcome);
    }

    [Fact(Timeout = 30000)]
    public async Task A_transfer_is_bounded_by_the_connector_even_when_the_client_ignores_its_budget()
    {
        var time = new FakeTimeProvider();
        var client = new StallingWinRmClient();
        var connector = Build(client, time);

        var running = connector.PushAsync(
            Target(),
            new FileTransfer
            {
                RemotePath = @"C:\temp\payload.bin",
                Content = new byte[] { 1, 2, 3 },
                Timeout = TimeSpan.FromMinutes(2),
            },
            CancellationToken.None);

        await client.Entered;
        time.Advance(TimeSpan.FromMinutes(3));

        var result = await Settled(running, "the transfer");
        Assert.Equal(ConnectorOutcome.Timeout, result.Outcome);
    }

    /// <summary>
    /// The probe honours the CONFIGURED budget, not a literal. With the old compiled-in 15 seconds,
    /// advancing a fake clock by 3 would never reach the deadline and this could not complete.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task The_probe_honours_the_configured_budget_rather_than_a_compiled_in_one()
    {
        var time = new FakeTimeProvider();
        var client = new StallingWinRmClient();
        var connector = Build(
            client,
            time,
            new ConnectorTimeoutOptions
            {
                Reachability = TimeSpan.FromSeconds(1),
                Authentication = TimeSpan.FromSeconds(1),
            });

        var probing = connector.TestConnectivityAsync(Target(), CancellationToken.None);

        await client.Entered;

        time.Advance(TimeSpan.FromMilliseconds(1_500)); // inside the configured 2s ProbeBudget
        Assert.False(probing.IsCompleted, "the probe gave up before its configured budget elapsed");

        time.Advance(TimeSpan.FromSeconds(1)); // past it

        var result = await Settled(probing, "the probe");
        Assert.Equal(ConnectorOutcome.Timeout, result.Outcome);
    }

    [Fact(Timeout = 30000)]
    public async Task Caller_cancellation_is_not_collapsed_into_a_timeout()
    {
        var client = new StallingWinRmClient();
        var connector = Build(client, TimeProvider.System);

        using var cts = new CancellationTokenSource();
        var running = connector.RunAsync(
            Target(),
            new RemoteCommand { CommandLine = "whoami", Timeout = TimeSpan.FromMinutes(10) },
            cts.Token);

        await client.Entered;
        await cts.CancelAsync();

        // "I stopped this" and "the endpoint did not answer" mean different things to a wave.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
    }

    /// <summary>
    /// Bounded await with a named failure. An unbounded one would hang the suite instead of failing
    /// it — the exact defect that stopped this phase's unit project from ever completing.
    /// </summary>
    private static async Task<T> Settled<T>(Task<T> operation, string what)
    {
        var settled = await Task.WhenAny(operation, Task.Delay(TimeSpan.FromSeconds(5)));

        Assert.True(
            settled == operation,
            $"{what} never expired after its budget elapsed on the fake clock, so the connector is "
            + "relying on the client to bound itself rather than bounding it.");

        return await operation;
    }

    private static EndpointTarget Target() => new()
    {
        TenantId = ConnectorHarness.Tenant,
        Host = "winhost.example.net",
        Port = 5986,
        Protocol = EndpointProtocol.WinRm,
        Credential = ConnectorHarness.LoginCredential,
    };

    private static WinRmConnector Build(
        IWinRmClient client, TimeProvider time, ConnectorTimeoutOptions? timeouts = null)
    {
        var credentials = new FakeCredentialProvider();
        credentials.AddSecret(
            ConnectorHarness.LoginCredential, "s3cr3t", CredentialKind.WindowsPassword, "Administrator");

        var options = Options.Create(new ConnectorConcurrencyOptions());

        return new WinRmConnector(
            credentials,
            client,
            new SemaphoreConnectionGovernor(options),
            new KeyedOperationCoordinator(),
            NullLogger<WinRmConnector>.Instance,
            timeouts,
            time);
    }
}
