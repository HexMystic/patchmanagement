using Microsoft.Extensions.Time.Testing;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests.Cancellation;

/// <summary>
/// Exit criterion (d): a hung operation is cancelled. CLAUDE.md NEVER #5 — every endpoint operation
/// is time-bounded, no unbounded remote wait ever.
///
/// <para>Nothing here sleeps. The operation is observed in flight via
/// <see cref="StallingSshSession.Entered"/>, and deadlines are driven by advancing a
/// <see cref="FakeTimeProvider"/>. A timeout test that waits in real time is slow, and slow tests
/// accumulate margin until they no longer assert anything about timeouts.</para>
/// </summary>
public sealed class TimeoutTests
{
    [Fact]
    public async Task A_command_that_exceeds_its_budget_is_reported_as_a_timeout()
    {
        var time = new FakeTimeProvider();
        var stalled = new StallingSshSession();
        var harness = ConnectorHarness.Build(session: () => stalled, timeProvider: time);

        var running = harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "sleep 600", Timeout = TimeSpan.FromSeconds(30) },
            CancellationToken.None);

        await stalled.Entered;           // the command is genuinely in flight
        time.Advance(TimeSpan.FromSeconds(31)); // its budget elapses

        var result = await running;

        // A timeout is an honest outcome, not an exception thrown at the caller: the operation was
        // dispatched and its fate is unknown, which the state machine has a state for.
        Assert.Equal(ConnectorOutcome.Timeout, result.Outcome);
    }

    [Fact]
    public async Task A_timed_out_command_releases_its_connection_lease()
    {
        var time = new FakeTimeProvider();
        var stalled = new StallingSshSession();
        var harness = ConnectorHarness.Build(session: () => stalled, timeProvider: time);

        var running = harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "sleep 600", Timeout = TimeSpan.FromSeconds(30) },
            CancellationToken.None);

        await stalled.Entered;
        time.Advance(TimeSpan.FromSeconds(31));
        await running;

        // A lease leaked on the timeout path is the worst kind: timeouts happen when an estate is
        // already struggling, so the budget would drain exactly when it is most needed.
        Assert.Equal(0, harness.Governor.ActiveGlobal);
        Assert.Equal(0, harness.Governor.ActiveForTenant(ConnectorHarness.Tenant));
    }

    [Fact]
    public async Task Caller_cancellation_surfaces_as_cancellation_not_as_a_timeout()
    {
        var stalled = new StallingSshSession();
        var harness = ConnectorHarness.Build(session: () => stalled);

        using var cts = new CancellationTokenSource();
        var running = harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "sleep 600", Timeout = TimeSpan.FromMinutes(10) },
            cts.Token);

        await stalled.Entered;
        cts.Cancel();

        // The distinction matters to the caller: "I stopped this" and "the endpoint did not answer
        // in time" have different meanings for a wave, and collapsing them would make a cancelled
        // deployment look like an unreachable estate.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
        Assert.Equal(0, harness.Governor.ActiveGlobal);
    }

    [Fact]
    public async Task A_transfer_that_exceeds_its_budget_times_out_and_leaks_no_lease()
    {
        var time = new FakeTimeProvider();
        var stalled = new StallingSshSession();
        var harness = ConnectorHarness.Build(session: () => stalled, timeProvider: time);

        var running = harness.Connector.PushAsync(
            ConnectorHarness.Target(),
            new FileTransfer
            {
                RemotePath = "/tmp/payload.bin",
                Content = new byte[] { 1, 2, 3 },
                Timeout = TimeSpan.FromMinutes(2),
            },
            CancellationToken.None);

        await stalled.Entered;
        time.Advance(TimeSpan.FromMinutes(3));

        var result = await running;

        Assert.Equal(ConnectorOutcome.Timeout, result.Outcome);
        Assert.Equal(0, harness.Governor.ActiveGlobal);
    }

    [Fact]
    public async Task The_connectivity_probe_honours_its_configured_budget_rather_than_a_compiled_in_one()
    {
        var time = new FakeTimeProvider();
        var stalled = new StallingSshSession();
        var harness = ConnectorHarness.Build(
            session: () => stalled,
            timeProvider: time,
            timeouts: new ConnectorTimeoutOptions { Connectivity = TimeSpan.FromSeconds(2) });

        var probing = harness.Connector.TestConnectivityAsync(ConnectorHarness.Target(), CancellationToken.None);

        await stalled.Entered;

        // Two seconds is enough for the CONFIGURED budget but nowhere near the 15 seconds that used
        // to be compiled in. If the literal were still there this would not complete.
        time.Advance(TimeSpan.FromSeconds(3));

        var result = await probing;
        Assert.Equal(ConnectorOutcome.Timeout, result.Outcome);
    }

    [Fact]
    public async Task A_command_that_completes_inside_its_budget_is_not_disturbed_by_the_clock()
    {
        var time = new FakeTimeProvider();
        var harness = ConnectorHarness.Build(timeProvider: time);

        var result = await harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "id -u", Timeout = TimeSpan.FromSeconds(30) },
            CancellationToken.None);

        // The control. Without it every assertion above would still hold for a connector that timed
        // out unconditionally.
        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
    }
}
