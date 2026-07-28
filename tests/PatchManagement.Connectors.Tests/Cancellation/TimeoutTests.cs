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

    /// <summary>
    /// The probe's budget comes from configuration, and the stall is in the CONNECT — which is where
    /// a probe actually spends its time.
    ///
    /// <para><b>This test used to hang forever.</b> It stalled the <em>session</em> and awaited
    /// <see cref="StallingSshSession.Entered"/>, but <c>TestConnectivityAsync</c> never runs a session
    /// operation — reaching an authenticated session IS the proof — so that signal could never fire.
    /// It had no timeout either, so the suite did not fail, it stopped: the whole connector project
    /// never reached a result, and the phase's recorded "267 passing, 0 skipped" described a run that
    /// cannot have happened. A hanging test is worse than a failing one precisely because it reads as
    /// broken infrastructure. Hence <c>Timeout</c> below, and a fake that can hold a probe open.</para>
    ///
    /// <para>The budget is walked from both sides — not yet expired, then expired — so the assertion
    /// is about the boundary rather than about eventually finishing.</para>
    /// </summary>
    [Fact(Timeout = 10000)]
    public async Task The_connectivity_probe_honours_its_configured_budget_rather_than_a_compiled_in_one()
    {
        var time = new FakeTimeProvider();
        var factory = new StallingSshSessionFactory();
        var harness = ConnectorHarness.Build(
            sessionFactory: factory,
            timeProvider: time,
            timeouts: new ConnectorTimeoutOptions
            {
                Reachability = TimeSpan.FromSeconds(1),
                Authentication = TimeSpan.FromSeconds(1),
            });

        var probing = harness.Connector.TestConnectivityAsync(ConnectorHarness.Target(), CancellationToken.None);

        await factory.Entered; // the probe is genuinely mid-connect

        // Still INSIDE the configured 2s ProbeBudget: abandoning here would mean the connector is
        // enforcing some shorter budget of its own rather than the configured one.
        time.Advance(TimeSpan.FromMilliseconds(1_500));
        Assert.False(probing.IsCompleted, "the probe gave up before its configured budget elapsed");

        // Past it.
        time.Advance(TimeSpan.FromSeconds(1));

        // Bounded, and the bound is load-bearing rather than belt-and-braces: with a compiled-in
        // literal the fake clock never reaches the deadline, so `await probing` would simply never
        // return. Without this the failure is a bare "test execution timed out", which names neither
        // the guarantee nor the cause; with it, the assertion says which budget is being enforced.
        var settled = await Task.WhenAny(probing, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.True(
            settled == probing,
            "The probe did not expire after its configured 2s budget elapsed on the fake clock, so the "
            + "budget it enforces is not the configured one — which is exactly how a compiled-in "
            + "literal behaves.");

        var result = await probing;
        Assert.Equal(ConnectorOutcome.Timeout, result.Outcome);
    }

    /// <summary>
    /// An unmodelled transport exception is contained as a typed result rather than thrown.
    ///
    /// <para>SSH.NET threw <c>InvalidOperationException</c> from the stdin path and it escaped
    /// <c>RunAsync</c> raw — past a contract that promises typed results, and into ASP.NET's logger
    /// outside any redaction scope. The ordering bug is fixed, but "the transport only throws what we
    /// translate" was the assumption that let it out, so the boundary no longer relies on it.</para>
    /// </summary>
    [Fact]
    public async Task An_unmodelled_transport_exception_is_contained_as_a_typed_result()
    {
        var harness = ConnectorHarness.Build(
            session: () => new ThrowingSshSession(new InvalidOperationException("transport misbehaved")));

        var result = await harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "id -u" },
            CancellationToken.None);

        Assert.Equal(ConnectorOutcome.ProtocolError, result.Outcome);
        Assert.Equal(ConnectorReason.TransportFault, result.Detail);

        // The exception's own text must not ride along into Detail — a caller logs that, and the
        // connector cannot know what a transport put in a message.
        Assert.DoesNotContain("misbehaved", result.Detail ?? string.Empty, StringComparison.Ordinal);

        // ...and the lease is still returned, which is the failure mode that hurts at scale.
        Assert.Equal(0, harness.Governor.ActiveGlobal);
    }

    /// <summary>The transfer half of the same guarantee — an SFTP fault must not escape either.</summary>
    [Fact]
    public async Task An_unmodelled_transport_exception_during_a_transfer_is_contained_too()
    {
        var harness = ConnectorHarness.Build(
            session: () => new ThrowingSshSession(new InvalidOperationException("sftp misbehaved")));

        var result = await harness.Connector.PushAsync(
            ConnectorHarness.Target(),
            new FileTransfer { RemotePath = "/tmp/x.bin", Content = new byte[] { 1, 2, 3 } },
            CancellationToken.None);

        Assert.Equal(ConnectorOutcome.ProtocolError, result.Outcome);
        Assert.Equal(ConnectorReason.TransportFault, result.Detail);
        Assert.Equal(0, harness.Governor.ActiveGlobal);
    }

    /// <summary>
    /// The control that keeps the containment honest: caller cancellation is NOT a transport fault and
    /// must still propagate. A catch-all that swallowed it would turn "I stopped this" into "the
    /// endpoint misbehaved" — the exact collapse the timeout tests above exist to prevent.
    /// </summary>
    [Fact]
    public async Task Containment_does_not_swallow_caller_cancellation()
    {
        var stalled = new StallingSshSession();
        var harness = ConnectorHarness.Build(session: () => stalled);

        using var cts = new CancellationTokenSource();
        var running = harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "sleep 600", Timeout = TimeSpan.FromMinutes(10) },
            cts.Token);

        await stalled.Entered;
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
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
