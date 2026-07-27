using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests.Concurrency;

/// <summary>
/// Exit criterion (e): the concurrency limiter caps simultaneous sessions.
///
/// <para>Each operation targets a DIFFERENT host, so each genuinely needs its own session. Pointing
/// them all at one host would let the pool serve every one from a single reused transport, the peak
/// would be 1, and the test would pass without the governor doing anything at all.</para>
/// </summary>
public sealed class SessionCapTests
{
    private const int GlobalMax = 3;
    private const int Operations = 12;

    [Fact]
    public async Task The_connector_never_opens_more_concurrent_sessions_than_the_global_budget()
    {
        // One gate shared by every session. The budget admits work in waves, so sessions keep being
        // created after the first batch; releasing only the ones visible at a single instant would
        // leave the later arrivals stalled and hang the test.
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var factory = new ControllableSshSessionFactory(() => new StallingSshSession(gate));

        var connector = BuildConnector(factory, out var governor);
        using var _ = governor;

        var running = Enumerable.Range(0, Operations)
            .Select(i => connector.RunAsync(
                TargetOnPort(2200 + i),
                new RemoteCommand { CommandLine = "id -u", Timeout = TimeSpan.FromMinutes(5) },
                CancellationToken.None))
            .ToList();

        // Wait for the budget to fill — an observed fact, not a duration.
        await factory.OperationsReach(GlobalMax).WaitAsync(TimeSpan.FromSeconds(10));

        // Exactly the budget is in flight and the rest are queued behind it. Without the cap all
        // twelve would already be running.
        Assert.Equal(GlobalMax, factory.OperationsStarted);
        Assert.Equal(GlobalMax, governor.ActiveGlobal);
        Assert.Equal(Operations - GlobalMax, governor.WaitingGlobal);

        // Let everything drain, then assert on the high-water mark: a fact about overlap that
        // already happened, rather than a snapshot the test hoped to catch at the right moment.
        gate.SetResult();
        await Task.WhenAll(running).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.True(
            factory.PeakConcurrentOperations <= GlobalMax,
            $"{factory.PeakConcurrentOperations} operations ran at once against a budget of {GlobalMax}.");
        Assert.Equal(Operations, factory.OperationsStarted);
        Assert.Equal(0, governor.ActiveGlobal);
    }

    private static SshConnector BuildConnector(
        ControllableSshSessionFactory factory, out SemaphoreConnectionGovernor governor)
    {
        var credentials = new FakeCredentialProvider();
        credentials.Add(
            ConnectorHarness.LoginCredential, "key"u8.ToArray(), CredentialKind.SshKey, "labadmin");

        var options = Options.Create(new ConnectorConcurrencyOptions
        {
            GlobalMaxConnections = GlobalMax,
            PerTenantMaxConnections = 100,
            PerHostMaxConnections = 100,
        });

        governor = new SemaphoreConnectionGovernor(options);

        return new SshConnector(
            credentials,
            factory,
            new SshConnectionPool(options),
            governor,
            new KeyedOperationCoordinator(),
            NullLogger<SshConnector>.Instance);
    }

    private static EndpointTarget TargetOnPort(int port) => new()
    {
        TenantId = ConnectorHarness.Tenant,
        Host = "localhost",
        Port = port,
        Protocol = EndpointProtocol.Ssh,
        Credential = ConnectorHarness.LoginCredential,
    };
}
