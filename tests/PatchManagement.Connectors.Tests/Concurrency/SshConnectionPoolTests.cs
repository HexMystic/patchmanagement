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
}
