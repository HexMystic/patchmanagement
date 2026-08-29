using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests.Concurrency;

/// <summary>
/// D-310, resolved by measurement — and these tests pin the answer so it cannot be undone by
/// someone re-reasoning about it later.
///
/// <para><b>The question.</b> <c>AcquireAsync</c> called <c>EvictIdle()</c> on every borrow.
/// <c>EvictIdle</c> takes the pool's lifetime lock and walks every entry, so acquires serialised on
/// an O(entries) scan at exactly the point this product is supposed to scale (CLAUDE.md §2). The
/// deferral suspected the call was simply redundant once a timer evicted quiet pools, and refused to
/// settle it by argument: <i>"Measurement, not reasoning."</i></para>
///
/// <para><b>The answer: it was NOT redundant, and it was removed anyway.</b> Both halves were
/// measured on 2026-08-29 (2,000 borrows, in-memory sessions, no sockets):</para>
///
/// <code>
///                    with per-borrow sweep        without
///   100 entries        10.3 us/borrow            2.6 us/borrow
///   1,000 entries      81.9 us/borrow            2.2 us/borrow
///   5,000 entries     330.2 us/borrow            1.9 us/borrow
/// </code>
///
/// <para>The cost is linear in pool size and the saving is not: without the sweep a borrow is O(1)
/// and flat, roughly 174x cheaper at 5,000 entries. What it buys is a timing difference that is real
/// but <b>bounded</b> — an entry that has become eligible now waits for the next timer tick instead
/// of being evicted by the next borrow, so an idle session lives at most one extra
/// <c>PooledSessionIdleTimeout</c> (10 minutes rather than 5, at the default).</para>
///
/// <para><b>What decided it</b> was that removing the call broke no pre-existing test — only the two
/// written here to measure it. A bounded extra idle lifetime on a host nobody is talking to is worth
/// far less than an O(1) acquire on the path every wave takes.</para>
/// </summary>
public sealed class PoolEvictionTimingTests
{
    private static readonly TimeSpan Idle = TimeSpan.FromMinutes(5);

    private static SshConnectionPool Pool(FakeTimeProvider time) =>
        new(Options.Create(new ConnectorConcurrencyOptions { PooledSessionIdleTimeout = Idle }), time);

    private static async Task BorrowAndReleaseAsync(SshConnectionPool pool, string key, ISshSession session)
    {
        using (await pool.AcquireAsync(key, _ => Task.FromResult(session), CancellationToken.None))
        {
        }
    }

    /// <summary>
    /// The behaviour change, asserted rather than left implicit: an entry that is already eligible is
    /// NOT evicted by an unrelated borrow. It waits for the timer.
    ///
    /// <para>The window is constructed, not stumbled on. Ticks fall on period boundaries from
    /// construction (t=5, t=10, …); an entry last used at t=3 becomes eligible at t=8, which is after
    /// the t=5 tick and before the t=10 one. A borrow at t=9 is therefore the only place the two
    /// designs can be told apart — which is why a casually written version of this test would pass
    /// either way and prove nothing.</para>
    ///
    /// <para>The advance is stepped for the same reason. <see cref="FakeTimeProvider"/> moves its
    /// clock to the END of an <c>Advance</c> before running the timers that came due inside it, so one
    /// 6-minute jump would run the t=5 sweep against a t=9 clock and evict the entry there, closing
    /// the window. Landing on the tick keeps each sweep honest about what time it is.</para>
    /// </summary>
    [Fact]
    public async Task An_eligible_entry_waits_for_the_timer_rather_than_being_evicted_by_an_unrelated_borrow()
    {
        var time = new FakeTimeProvider();
        await using var pool = Pool(time);

        var idle = new RecordingSshSession();

        time.Advance(TimeSpan.FromMinutes(3));
        await BorrowAndReleaseAsync(pool, "tenant|a:22#cred@-", idle);

        time.Advance(TimeSpan.FromMinutes(2));    // t=5: tick runs, cutoff t=0, entry survives
        Assert.False(idle.Disposed, "evicted at t=5, when it had been idle only 2 of its 5 minutes");

        time.Advance(TimeSpan.FromMinutes(4));    // t=9: eligible since t=8, next tick not until t=10
        Assert.False(idle.Disposed, "the timer evicted it already — the measurement window is wrong");

        await BorrowAndReleaseAsync(pool, "tenant|b:22#cred@-", new RecordingSshSession());

        Assert.False(
            idle.Disposed,
            "a borrow swept the pool. The per-borrow EvictIdle was removed under D-310 because it "
            + "cost O(entries) under the lifetime lock on every acquire; reinstating it makes each "
            + "borrow scan the whole pool again.");
    }

    /// <summary>
    /// The bound that makes the change above acceptable, and the reason it is not simply a leak: an
    /// eligible entry never survives the tick after it becomes eligible, whether or not anything ever
    /// borrows again. The extra lifetime is one period, not unbounded.
    /// </summary>
    [Fact]
    public async Task An_eligible_entry_never_outlives_the_tick_after_it_becomes_eligible()
    {
        var time = new FakeTimeProvider();
        await using var pool = Pool(time);

        var idle = new RecordingSshSession();
        time.Advance(TimeSpan.FromMinutes(3));
        await BorrowAndReleaseAsync(pool, "tenant|a:22#cred@-", idle);

        time.Advance(TimeSpan.FromMinutes(2));   // t=5
        time.Advance(TimeSpan.FromMinutes(5));   // t=10, the tick after eligibility at t=8

        Assert.True(idle.Disposed, "nothing evicted it — the timer is the only thing left that can");
        Assert.Equal(0, pool.PooledSessionCount);
    }

    /// <summary>
    /// The property gained, counted rather than timed. A stopwatch assertion would measure the CI
    /// machine as much as the pool and would eventually be re-run until green, which is how a
    /// performance test becomes decoration; a scan count is exact and cannot flake.
    ///
    /// <para>This is the regression guard for the whole deferral: it fails the moment anything makes
    /// acquiring walk the pool again, and says why.</para>
    /// </summary>
    [Fact]
    public async Task Acquiring_does_not_scan_the_pool()
    {
        const int Entries = 200;
        const int Borrows = 10;

        var time = new FakeTimeProvider();
        await using var pool = Pool(time);

        for (var i = 0; i < Entries; i++)
            await BorrowAndReleaseAsync(pool, $"tenant|h{i}:22#cred@-", new RecordingSshSession());

        Assert.Equal(Entries, pool.PooledSessionCount);

        var scannedBefore = pool.EntriesScanned;
        var sweepsBefore = pool.EvictionSweeps;

        for (var i = 0; i < Borrows; i++)
            await BorrowAndReleaseAsync(pool, $"tenant|h{i}:22#cred@-", new RecordingSshSession());

        Assert.Equal(sweepsBefore, pool.EvictionSweeps);
        Assert.Equal(
            scannedBefore,
            pool.EntriesScanned);
    }

    /// <summary>
    /// The timer still sweeps — the counter above must not read zero merely because eviction stopped
    /// happening at all. Without this, deleting <c>EvictIdle</c> outright would pass every other test
    /// in this class.
    /// </summary>
    [Fact]
    public async Task The_timer_still_sweeps_the_pool_on_its_own()
    {
        var time = new FakeTimeProvider();
        await using var pool = Pool(time);

        await BorrowAndReleaseAsync(pool, "tenant|a:22#cred@-", new RecordingSshSession());

        var before = pool.EvictionSweeps;
        time.Advance(TimeSpan.FromMinutes(5));

        Assert.True(
            pool.EvictionSweeps > before,
            "the eviction timer did not run, so nothing evicts idle sessions at all");
    }
}
