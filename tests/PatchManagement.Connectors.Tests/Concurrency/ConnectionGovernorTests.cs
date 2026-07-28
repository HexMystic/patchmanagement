using Microsoft.Extensions.Options;
using PatchManagement.Connectors.Concurrency;

namespace PatchManagement.Connectors.Tests.Concurrency;

/// <summary>
/// The connection budget — the scaling wall at 10,000 endpoints (CLAUDE.md §2).
///
/// <para>Every test here is deterministic by construction: none sleeps, and none asserts on elapsed
/// time. Waiters are observed through the governor's <c>WaiterRegistered</c> seam, so "the third
/// operation is queued" is a fact rather than a hope.</para>
/// </summary>
public sealed class ConnectionGovernorTests
{
    private static readonly Guid TenantA = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid TenantB = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002");
    private const string HostA = "localhost:2201";
    private const string HostB = "localhost:2202";

    private static SemaphoreConnectionGovernor Governor(int global = 100, int perTenant = 100, int perHost = 100) =>
        new(Options.Create(new ConnectorConcurrencyOptions
        {
            GlobalMaxConnections = global,
            PerTenantMaxConnections = perTenant,
            PerHostMaxConnections = perHost,
        }));

    /// <summary>
    /// Completes once <paramref name="expected"/> operations are counted as waiting.
    ///
    /// <para>The timeout is not belt-and-braces — it is load-bearing. If a change makes the acquire
    /// stop blocking, the waiter count rises and falls before this can observe it, and an untimed
    /// wait would hang the suite forever instead of failing. A concurrency test that hangs on
    /// regression is worse than one that fails: it looks like an infrastructure problem.</para>
    /// </summary>
    private static async Task WaitersReach(SemaphoreConnectionGovernor governor, int expected)
    {
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Check() { if (governor.WaitingGlobal >= expected) reached.TrySetResult(); }

        governor.WaiterRegistered += Check;
        try
        {
            Check(); // in case the waiter registered before we subscribed
            var completed = await Task.WhenAny(reached.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.True(
                completed == reached.Task,
                $"Timed out waiting for {expected} queued operation(s); WaitingGlobal is "
                + $"{governor.WaitingGlobal}. The acquire under test is no longer blocking.");
        }
        finally
        {
            governor.WaiterRegistered -= Check;
        }
    }

    [Fact]
    public async Task Acquiring_beyond_the_global_budget_queues_until_a_lease_is_released()
    {
        using var governor = Governor(global: 2);

        var first = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);
        var second = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);

        var third = governor.AcquireAsync(TenantA, HostA, CancellationToken.None);
        await WaitersReach(governor, 1);

        Assert.Equal(2, governor.ActiveGlobal);
        Assert.Equal(1, governor.WaitingGlobal);
        Assert.Equal(0, governor.AvailableGlobal);
        Assert.False(third.IsCompleted, "the third acquire must not complete while the budget is full");

        await first.DisposeAsync();
        var lease = await third;

        Assert.Equal(2, governor.ActiveGlobal);
        Assert.Equal(0, governor.WaitingGlobal);

        await second.DisposeAsync();
        await lease.DisposeAsync();
        Assert.Equal(0, governor.ActiveGlobal);
    }

    [Fact]
    public async Task One_tenant_at_its_ceiling_does_not_block_another_tenant()
    {
        using var governor = Governor(global: 10, perTenant: 1);

        await using var a = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);

        // Tenant A is full. Tenant B must be unaffected — this is the whole point of a per-tenant
        // dimension, and it is what the old global-first acquisition order silently broke.
        await using var b = await governor.AcquireAsync(TenantB, HostA, CancellationToken.None);

        Assert.Equal(1, governor.ActiveForTenant(TenantA));
        Assert.Equal(1, governor.ActiveForTenant(TenantB));
    }

    [Fact]
    public async Task The_per_host_cap_is_shared_across_tenants()
    {
        using var governor = Governor(global: 10, perTenant: 10, perHost: 1);

        await using var a = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);

        // A DIFFERENT tenant, the SAME host. Neither the global nor either per-tenant budget is
        // near its limit, so only a host dimension can hold this back. Without one, a single estate
        // could aim its whole per-tenant allowance at one machine and flatten it while every number
        // on the dashboard still looked healthy.
        var blocked = governor.AcquireAsync(TenantB, HostA, CancellationToken.None);
        await WaitersReach(governor, 1);

        Assert.False(blocked.IsCompleted, "a second tenant exceeded the per-host cap");
        Assert.Equal(1, governor.ActiveForHost(HostA));

        // ...and a different host is free, proving the cap is per-host rather than a global stall.
        await using var elsewhere = await governor.AcquireAsync(TenantB, HostB, CancellationToken.None);
        Assert.Equal(1, governor.ActiveForHost(HostB));

        await a.DisposeAsync();
        await using var released = await blocked;
    }

    [Fact]
    public async Task TryAcquire_refuses_instead_of_queueing_when_saturated()
    {
        using var governor = Governor(global: 1);

        await using var held = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);

        Assert.False(governor.TryAcquire(TenantA, HostA, out var refused));
        Assert.Null(refused);

        // A refusal must leave no trace: counters unchanged, and — critically — no permit consumed.
        // A TryAcquire that leaked a permit on the failure path would shrink the budget on every
        // refusal until the process stopped connecting entirely.
        Assert.Equal(1, governor.ActiveGlobal);
        Assert.Equal(0, governor.WaitingGlobal);

        await held.DisposeAsync();
        Assert.True(governor.TryAcquire(TenantA, HostA, out var granted));
        Assert.NotNull(granted);
        await granted!.DisposeAsync();
        Assert.Equal(0, governor.ActiveGlobal);
    }

    [Fact]
    public async Task A_waiter_cancelled_before_it_is_served_stops_being_counted_as_waiting()
    {
        using var governor = Governor(global: 1);

        await using var held = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);

        using var cts = new CancellationTokenSource();
        var queued = governor.AcquireAsync(TenantA, HostA, cts.Token);
        await WaitersReach(governor, 1);
        Assert.Equal(1, governor.WaitingGlobal);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);

        // If the decrement lived on the success path instead of in a finally, the queue depth would
        // drift permanently upward — and nothing ever reconciles it, so a scheduler throttling on
        // this number would throttle against a fiction that only grows.
        Assert.Equal(0, governor.WaitingGlobal);
        Assert.Equal(0, governor.WaitingForTenant(TenantA));
        Assert.Equal(1, governor.ActiveGlobal);
    }

    /// <summary>
    /// A waiter cancelled <b>after taking its tenant and host permits, while waiting for a global
    /// one</b> must hand all three back.
    ///
    /// <para><b>Cold review R2 finding #5: this test used to prove none of that.</b> It ran with
    /// <c>global: 1</c> and left the per-tenant and per-host budgets at their 100 default, so the
    /// waiter blocked on the GLOBAL semaphore — meaning it had never taken a global permit to leak —
    /// while any tenant or host permit it did leak vanished into 99 spare ones. Deleting the entire
    /// unwind block from <c>AcquireAsync</c> left this green.</para>
    ///
    /// <para>Three things fix that, and the third was not obvious. The budgets are now as small as the
    /// scenario allows, so ONE leaked permit is the difference between passing and failing; the global
    /// budget is exhausted by an <em>unrelated</em> tenant, so the waiter reaches the global wait
    /// holding its tenant and host permits — the state the unwind exists for; and a second lease on
    /// the same tenant and host is held throughout.</para>
    ///
    /// <para><b>That anchor lease is load-bearing.</b> Slots are reference-counted and pruned when the
    /// last reference goes, so a cancelled waiter that was the ONLY user takes the whole slot —
    /// semaphore and all — down with it on its way out. The next acquire builds a fresh slot at full
    /// capacity and the leak is erased. Pruning therefore hides exactly the defect this test is for,
    /// and a version of this test without the anchor still passed with the entire unwind deleted.</para>
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task A_cancelled_waiter_leaks_no_permit()
    {
        using var governor = Governor(global: 3, perTenant: 2, perHost: 2);

        // Keeps tenant A's and host A's slots referenced for the whole test, so a leaked permit stays
        // observable instead of being pruned away with the slot.
        var anchor = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);

        // Fill the global budget from another tenant entirely, so tenant A's waiter gets past its own
        // two dimensions and blocks on the shared one.
        var filler1 = await governor.AcquireAsync(TenantB, HostB, CancellationToken.None);
        var filler2 = await governor.AcquireAsync(TenantB, HostB, CancellationToken.None);
        Assert.Equal(0, governor.AvailableGlobal);

        using var cts = new CancellationTokenSource();
        var queued = governor.AcquireAsync(TenantA, HostA, cts.Token);
        await WaitersReach(governor, 1);

        // Right now it holds tenant A's second permit and host A's second permit, and wants a global
        // one. Both of those must come back.
        Assert.Equal(1, governor.WaitingForTenant(TenantA));

        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);

        await filler1.DisposeAsync();
        await filler2.DisposeAsync();

        // Tenant A takes the second of its two permits. With the old 100-wide budgets this could not
        // fail however many permits had leaked; at 2, with the anchor holding the first, it fails on
        // the very first one.
        var second = await Granted(governor, TenantA, HostA, "tenant A's second");

        Assert.Equal(2, governor.ActiveForTenant(TenantA));
        Assert.Equal(2, governor.ActiveForHost(HostA));

        await anchor.DisposeAsync();
        await second.DisposeAsync();
        Assert.Equal(0, governor.ActiveGlobal);
        Assert.Equal(0, governor.TrackedSlotCount);
    }

    /// <summary>
    /// Acquires with a bound, so a leaked permit fails the test by NAME instead of hanging it. An
    /// unbounded await here would stop the suite rather than fail it — the failure mode that hid the
    /// probe-budget defect for this whole phase.
    /// </summary>
    private static async Task<IConnectionLease> Granted(
        SemaphoreConnectionGovernor governor, Guid tenantId, string hostKey, string which)
    {
        var acquire = governor.AcquireAsync(tenantId, hostKey, CancellationToken.None);
        var settled = await Task.WhenAny(acquire, Task.Delay(TimeSpan.FromSeconds(5)));

        Assert.True(
            settled == acquire,
            $"{which} acquire never completed, so a cancelled waiter leaked a per-tenant or per-host "
            + "permit: the budget is permanently smaller than it is configured to be, and nothing "
            + "reconciles it.");

        return await acquire;
    }

    [Fact]
    public async Task Slots_are_pruned_once_nobody_holds_or_wants_them()
    {
        using var governor = Governor();

        var lease = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);
        Assert.True(governor.TrackedSlotCount > 0, "sanity: acquiring tracked no slot at all");

        await lease.DisposeAsync();

        // Retaining a slot per tenant and per host forever is an unbounded leak in a singleton that
        // lives as long as the process — on a 10,000-endpoint estate it is memory creeping upward
        // with nothing obvious to blame.
        Assert.Equal(0, governor.TrackedSlotCount);
    }

    [Fact]
    public async Task A_double_dispose_does_not_hand_back_a_permit_twice()
    {
        using var governor = Governor(global: 1);

        var lease = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);
        await lease.DisposeAsync();
        await lease.DisposeAsync();

        Assert.Equal(0, governor.ActiveGlobal);

        // Releasing twice would raise the ceiling above the configured budget — the cap would still
        // be reported as 1 while two operations ran.
        await using var one = await governor.AcquireAsync(TenantA, HostA, CancellationToken.None);
        Assert.False(governor.TryAcquire(TenantA, HostA, out _));
    }
}
