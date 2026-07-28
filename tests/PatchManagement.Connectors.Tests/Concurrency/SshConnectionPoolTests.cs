using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests.Concurrency;

/// <summary>
/// Session reuse. The pool exists because SSH multiplexes channels over one transport, so far fewer
/// TCP connections are opened than operations performed — which is the point at the 10,000-endpoint
/// scaling wall. What it must never do is let reuse cross a tenant boundary.
/// </summary>
public sealed class SshConnectionPoolTests
{
    private static readonly Guid OtherTenant = Guid.Parse("99999999-9999-9999-9999-999999999999");

    /// <summary>
    /// Two tenants pointed at the same host with the same credential reference must NOT share an
    /// authenticated session.
    ///
    /// <para><b>Why this test is worth more than it looks.</b> Before the key carried a tenant, the
    /// pool keyed on <c>host:port#credentialGuid</c>. Isolation therefore held only because
    /// credential ids happen to be unique per tenant in practice — an <em>incidental</em> property of
    /// the data, not an enforced one. Anything that made two tenants share a credential id (a
    /// restored backup, a seeded demo tenant, a future shared-credential feature, a test fixture)
    /// would silently hand tenant B an SSH session already authenticated as tenant A. Nothing in the
    /// pool would have objected, and no test would have noticed.</para>
    /// </summary>
    [Fact]
    public async Task A_second_tenant_does_not_reuse_the_first_tenants_authenticated_session()
    {
        var created = new List<RecordingSshSession>();
        var harness = ConnectorHarness.Build(session: () =>
        {
            var session = new RecordingSshSession();
            created.Add(session);
            return session;
        });

        var first = ConnectorHarness.Target();
        // Same host, same port, SAME credential reference — differing only by tenant.
        var second = first with { TenantId = OtherTenant };

        var command = new RemoteCommand { CommandLine = "id -u" };
        await harness.Connector.RunAsync(first, command, CancellationToken.None);
        await harness.Connector.RunAsync(second, command, CancellationToken.None);

        Assert.Equal(2, harness.SessionFactory.ConnectAttempts);
        Assert.Equal(2, created.Count);
        Assert.NotSame(created[0], created[1]);
    }

    [Fact]
    public async Task The_same_tenant_reuses_one_session_across_operations_on_the_same_host()
    {
        var harness = ConnectorHarness.Build();
        var target = ConnectorHarness.Target();
        var command = new RemoteCommand { CommandLine = "id -u" };

        await harness.Connector.RunAsync(target, command, CancellationToken.None);
        await harness.Connector.RunAsync(target, command, CancellationToken.None);

        // The control for the test above: if reuse never happened, cross-tenant isolation would be
        // trivially satisfied and would prove nothing about the key.
        Assert.Equal(1, harness.SessionFactory.ConnectAttempts);
    }

    [Fact]
    public async Task A_different_host_for_the_same_tenant_gets_its_own_session()
    {
        var harness = ConnectorHarness.Build();
        var first = ConnectorHarness.Target();
        var second = first with { Port = 2202 };

        var command = new RemoteCommand { CommandLine = "id -u" };
        await harness.Connector.RunAsync(first, command, CancellationToken.None);
        await harness.Connector.RunAsync(second, command, CancellationToken.None);

        Assert.Equal(2, harness.SessionFactory.ConnectAttempts);
    }

    [Fact]
    public async Task An_idle_session_is_evicted_by_the_timer_with_no_further_traffic()
    {
        var time = new FakeTimeProvider();
        var options = Options.Create(new ConnectorConcurrencyOptions
        {
            PooledSessionIdleTimeout = TimeSpan.FromMinutes(5),
        });

        await using var pool = new SshConnectionPool(options, time);
        var session = new RecordingSshSession();

        using (await pool.AcquireAsync("tenant|localhost:2201#cred@-", _ => Task.FromResult<ISshSession>(session), CancellationToken.None))
        {
        }

        Assert.Equal(1, pool.PooledSessionCount);
        Assert.False(session.Disposed);

        // Advance past the idle timeout WITHOUT touching the pool again. Eviction used to run only
        // at the top of AcquireAsync, so a pool that went quiet never evicted anything — the sessions
        // most deserving of cleanup, on hosts nobody was talking to, were precisely the ones nothing
        // came back to clean up, and they held an authenticated transport open until process exit.
        time.Advance(TimeSpan.FromMinutes(6));

        Assert.True(session.Disposed, "the idle session survived the timer; eviction still depends on traffic");
        Assert.Equal(0, pool.PooledSessionCount);
    }

    /// <summary>
    /// Shutdown must not close a transport out from under a running command.
    ///
    /// <para><b>Cold review R3.</b> <c>DisposeAsync</c> waited on each entry's gate but never checked
    /// <c>InUse</c>, so it disposed sessions that borrowers were still using — the gate is free during
    /// an operation, because <c>AcquireAsync</c> releases it before returning the lease. The borrower's
    /// in-flight call then hit a disposed <c>SshClient</c> and threw
    /// <see cref="ObjectDisposedException"/>, which <c>SshConnector.IsTransportFault</c> deliberately
    /// excludes as a caller bug — so it escaped untyped from an API whose whole contract is typed
    /// results (CLAUDE.md §5). Eviction already got this right (<c>A_session_still_in_use_is_not_evicted</c>);
    /// disposal did not.</para>
    ///
    /// <para>The fix is "last one out turns off the lights": disposal tears down what is idle and hands
    /// anything still borrowed to the returning lease, so a session is never closed under a borrower
    /// and never leaked either.</para>
    /// </summary>
    [Fact]
    public async Task Disposing_the_pool_does_not_close_a_session_a_borrower_is_still_using()
    {
        var pool = new SshConnectionPool(Options.Create(new ConnectorConcurrencyOptions()));
        var session = new RecordingSshSession();

        var borrowed = await pool.AcquireAsync(
            "tenant|localhost:2201#cred@-", _ => Task.FromResult<ISshSession>(session), CancellationToken.None);

        await pool.DisposeAsync();

        Assert.False(
            session.Disposed,
            "the pool closed a session while an operation still held it; that operation now faults with "
            + "ObjectDisposedException, which escapes the connector untyped");

        // Returning the lease must also not fault on a gate the pool disposed underneath it.
        var fault = Record.Exception(borrowed.Dispose);
        Assert.Null(fault);

        Assert.True(
            session.Disposed,
            "the last borrower returned and nothing tore the session down, so a disposed pool leaks an "
            + "authenticated transport for the process lifetime");
    }

    /// <summary>The ordinary case still tears down immediately: an idle session dies with the pool.</summary>
    [Fact]
    public async Task Disposing_the_pool_closes_a_session_nobody_is_using()
    {
        var pool = new SshConnectionPool(Options.Create(new ConnectorConcurrencyOptions()));
        var session = new RecordingSshSession();

        using (await pool.AcquireAsync(
            "tenant|localhost:2201#cred@-", _ => Task.FromResult<ISshSession>(session), CancellationToken.None))
        {
        }

        await pool.DisposeAsync();

        Assert.True(session.Disposed);
    }

    [Fact]
    public async Task A_session_still_in_use_is_not_evicted()
    {
        var time = new FakeTimeProvider();
        var options = Options.Create(new ConnectorConcurrencyOptions
        {
            PooledSessionIdleTimeout = TimeSpan.FromMinutes(5),
        });

        await using var pool = new SshConnectionPool(options, time);
        var session = new RecordingSshSession();

        using var borrowed = await pool.AcquireAsync(
            "tenant|localhost:2201#cred@-", _ => Task.FromResult<ISshSession>(session), CancellationToken.None);

        time.Advance(TimeSpan.FromMinutes(6));

        // Evicting a borrowed session would close the transport out from under a running command.
        Assert.False(session.Disposed);
    }

    /// <summary>
    /// Shutdown racing the eviction timer must not leave the evictor holding a freed gate.
    ///
    /// <para><b>Cold review R4.</b> <c>EvictIdle</c> opened with <c>if (_disposed) return;</c>, which is
    /// check-then-act: the evictor reads the flag, takes an entry out of the dictionary, and is then
    /// descheduled; <c>DisposeAsync</c> runs to completion and disposes that entry's gate; the evictor
    /// resumes and calls <c>Gate.Wait(0)</c> on it. <c>_entries.Clear()</c> does not help, because the
    /// evictor already holds the reference. R4 reproduced it in 150-286 randomised iterations —
    /// <c>ObjectDisposedException</c> thrown from <c>EvictIdle</c>, on a timer callback. Under the real
    /// <see cref="TimeProvider.System"/> that callback runs on a pool thread with no caller to catch
    /// it, so an unhandled exception there terminates the process during shutdown.</para>
    ///
    /// <para>A volatile flag cannot fix this; the flag was already volatile. The fix is mutual
    /// exclusion — the evictor holds the lifetime lock across its WHOLE sweep, so disposal either
    /// waits for the sweep to finish or the sweep starts after the flag is set and returns at once.
    /// There is no third interleaving.</para>
    ///
    /// <para>The loop is randomised rather than choreographed on purpose: the window sits between two
    /// adjacent statements with no seam to inject at, so the only honest way to exercise it is to run
    /// the race many times. It exits early on the first fault, so this is fast when it is red.</para>
    /// </summary>
    [Fact]
    public async Task The_eviction_timer_cannot_touch_a_gate_that_disposal_has_freed()
    {
        var faults = new ConcurrentBag<Exception>();
        var completed = 0;

        for (var i = 0; i < 20_000 && faults.IsEmpty; i++)
        {
            var time = new FakeTimeProvider();
            var options = Options.Create(new ConnectorConcurrencyOptions
            {
                PooledSessionIdleTimeout = TimeSpan.FromMinutes(5),
            });

            var pool = new SshConnectionPool(options, time);

            // Borrow and return, so the entry is idle and past the cutoff — i.e. genuinely evictable.
            using (await pool.AcquireAsync(
                       "tenant|localhost:2201#cred@-",
                       _ => Task.FromResult<ISshSession>(new RecordingSshSession()),
                       CancellationToken.None))
            {
            }

            using var start = new ManualResetEventSlim(false);

            // Advancing the fake clock runs the eviction callback synchronously on THIS thread, which
            // is what lets it race a disposal running on another.
            var evicting = Task.Run(() =>
            {
                start.Wait();
                try { time.Advance(TimeSpan.FromMinutes(6)); }
                catch (Exception ex) { faults.Add(ex); }
            });

            var disposing = Task.Run(async () =>
            {
                start.Wait();
                try { await pool.DisposeAsync(); }
                catch (Exception ex) { faults.Add(ex); }
            });

            start.Set();
            await Task.WhenAll(evicting, disposing);
            completed++;
        }

        Assert.True(
            faults.IsEmpty,
            $"eviction and disposal raced into a freed gate after {completed} iteration(s). On the real "
            + "system timer this exception has no caller and takes the process down at shutdown:"
            + $"{Environment.NewLine}{string.Join(Environment.NewLine, faults.Select(f => f.ToString()))}");
    }
}
