using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors.Concurrency;

namespace PatchManagement.Connectors.Ssh;

/// <summary>
/// Reuses authenticated <see cref="ISshSession"/>s keyed by connection identity. SSH multiplexes
/// independent channels over one transport, so a single pooled session safely serves several
/// concurrent commands — the connector opens far fewer TCP connections than operations, which is
/// exactly what matters at the 10,000-endpoint scaling wall (CLAUDE.md §2). Absolute concurrency is
/// still bounded by the <see cref="IConnectionGovernor"/>; this pool only governs <i>reuse</i>.
///
/// Idle sessions (no in-flight borrowers, untouched past the configured idle timeout) are evicted
/// and disposed. A dead session is transparently reconnected on next borrow.
/// </summary>
internal sealed class SshConnectionPool : IAsyncDisposable
{
    private readonly ConnectorConcurrencyOptions _options;
    private readonly ConcurrentDictionary<string, PoolEntry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private readonly ITimer _evictionTimer;

    /// <summary>
    /// Makes an eviction sweep and pool disposal mutually exclusive.
    ///
    /// <para><b>A flag cannot do this job, and it was already volatile when it failed.</b>
    /// <c>EvictIdle</c> used to open with <c>if (_disposed) return;</c> — check-then-act. The evictor
    /// read the flag, took an entry out of the dictionary, and could then be descheduled while
    /// <see cref="DisposeAsync"/> ran to completion and disposed that entry's gate; the evictor resumed
    /// and waited on it. Clearing <c>_entries</c> does not close the window, because the evictor is
    /// already holding the reference. Cold review R4 reproduced it in 150-286 randomised iterations:
    /// <see cref="ObjectDisposedException"/> out of a timer callback, which under
    /// <see cref="TimeProvider.System"/> has no caller and terminates the process at shutdown.</para>
    ///
    /// <para>The evictor holds this for its ENTIRE sweep, so only two interleavings exist: the sweep
    /// completes before disposal sets the flag, or it starts afterwards and returns immediately.
    /// Lock order is always this lock and then an entry gate — the evictor takes gates with
    /// <c>Wait(0)</c> and never blocks, and disposal waits on gates only after releasing this — so the
    /// two cannot deadlock.</para>
    /// </summary>
    private readonly object _lifetime = new();

    /// <summary>
    /// Written under <see cref="_lifetime"/>. Volatile only for the advisory fast-path read in
    /// <see cref="AcquireAsync"/>; the lock, not this flag, is what makes eviction safe.
    /// </summary>
    private volatile bool _disposed;

    /// <summary>
    /// <paramref name="timeProvider"/> is injected so eviction is testable without waiting in real
    /// time: a test advances a <c>FakeTimeProvider</c> and asserts the session was disposed, rather
    /// than sleeping for the idle timeout and hoping.
    /// </summary>
    public SshConnectionPool(IOptions<ConnectorConcurrencyOptions> options, TimeProvider? timeProvider = null)
    {
        _options = options.Value;
        _time = timeProvider ?? TimeProvider.System;

        // Eviction ran only at the top of AcquireAsync, so a pool that went quiet never evicted
        // anything: the sessions most deserving of cleanup — on a host nobody is talking to — were
        // exactly the ones nothing came back to clean up. They held an authenticated transport and a
        // file handle open until the process exited. A timer closes that.
        var period = _options.PooledSessionIdleTimeout;
        _evictionTimer = _time.CreateTimer(_ => EvictIdle(), state: null, dueTime: period, period: period);
    }

    /// <summary>Count of live pooled sessions (instrumentation/tests).</summary>
    public int PooledSessionCount => _entries.Values.Count(e => e.Session is { IsConnected: true });

    /// <summary>
    /// Total entries examined by every eviction sweep so far (instrumentation/tests).
    ///
    /// <para>Exists because D-310 is a <b>measurement</b>, and the cost of a sweep is work done, not
    /// seconds elapsed. Counting is what makes that measurable in a suite: a stopwatch assertion
    /// measures the machine as much as the pool, and a perf test that flakes is one people re-run
    /// until it passes. See <c>PoolEvictionTimingTests</c>.</para>
    /// </summary>
    public long EntriesScanned => Interlocked.Read(ref _entriesScanned);

    /// <summary>Number of eviction sweeps that have run (instrumentation/tests).</summary>
    public long EvictionSweeps => Interlocked.Read(ref _evictionSweeps);

    private long _entriesScanned;
    private long _evictionSweeps;

    /// <summary>
    /// Borrow a shared session for <paramref name="key"/>, creating it via <paramref name="connect"/>
    /// if none is cached or the cached one is dead. Dispose the returned lease when the operation
    /// finishes; the underlying session stays open for reuse.
    ///
    /// <para><b>Borrowing does not sweep (D-310, resolved by measurement 2026-08-29).</b> This used
    /// to call <c>EvictIdle()</c> first, which takes <see cref="_lifetime"/> and walks every entry —
    /// so acquires serialised on an O(entries) scan at the one place this product has to scale.
    /// Measured over 2,000 borrows: 10.3us/borrow at 100 entries, 81.9 at 1,000, 330.2 at 5,000,
    /// against a flat ~2us with the call gone. The sweep was NOT redundant — an eligible entry now
    /// waits for the next tick instead of going at the next borrow — but that costs at most one extra
    /// <c>PooledSessionIdleTimeout</c> of life for a session on a host nobody is talking to, and it
    /// broke no pre-existing test. See <c>PoolEvictionTimingTests</c>.</para>
    /// </summary>
    public async Task<PooledSessionLease> AcquireAsync(
        string key,
        Func<CancellationToken, Task<ISshSession>> connect,
        CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var entry = _entries.GetOrAdd(key, _ => new PoolEntry(_time));
        await entry.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (entry.Session is null || !entry.Session.IsConnected)
            {
                entry.Session?.Dispose();
                entry.Session = await connect(ct).ConfigureAwait(false);
            }

            entry.InUse++;
            entry.LastUsed = _time.GetUtcNow();
            return new PooledSessionLease(entry, entry.Session);
        }
        finally
        {
            entry.Gate.Release();
        }
    }

    private void EvictIdle()
    {
        // Disposing the timer does not wait for a callback already running, so a tick can still be in
        // here while DisposeAsync is tearing entries down. The lock is held across the WHOLE sweep —
        // not just the flag check — because the hazard is the gap between reading the flag and using
        // an entry, not the read itself. See _lifetime.
        List<PoolEntry>? doomed = null;

        lock (_lifetime)
        {
            if (_disposed) return;

            Interlocked.Increment(ref _evictionSweeps);
            Interlocked.Add(ref _entriesScanned, _entries.Count);

            var cutoff = _time.GetUtcNow() - _options.PooledSessionIdleTimeout;
            foreach (var (key, entry) in _entries)
            {
                if (entry.InUse != 0 || entry.LastUsed > cutoff)
                    continue;

                if (!entry.Gate.Wait(0))
                    continue;
                try
                {
                    // Removing it from _entries under the lock is what makes the deferred close safe:
                    // DisposeAsync only ever walks _entries, so an entry taken out here can no longer
                    // be seen — let alone have its gate freed — by a disposal that starts afterwards.
                    if (entry.InUse == 0 && entry.LastUsed <= cutoff && _entries.TryRemove(key, out _))
                        (doomed ??= []).Add(entry);
                }
                finally
                {
                    entry.Gate.Release();
                }
            }
        }

        // Closing a transport is network I/O and can block. Holding the lifetime lock across it would
        // stall every AcquireAsync on the pool — and connection concurrency, not the database, is the
        // wall at 10,000 endpoints (CLAUDE.md §2). These entries are already unreachable, so nothing
        // needs the lock held while they are closed.
        foreach (var entry in doomed ?? [])
        {
            entry.Session?.Dispose();
            entry.Session = null;
        }
    }

    /// <summary>
    /// Tears the pool down, closing every session nobody is using and handing anything still borrowed
    /// to the borrower that returns it — "last one out turns off the lights".
    ///
    /// <para><b>This used to dispose sessions regardless of <c>InUse</c>.</b> The gate is free while an
    /// operation runs — <see cref="AcquireAsync"/> releases it before handing back the lease — so
    /// waiting on it proved nothing, and shutdown closed transports out from under in-flight commands.
    /// The borrower then faulted on a disposed client with <see cref="ObjectDisposedException"/>, which
    /// <c>SshConnector</c> deliberately does not treat as a transport fault (it is normally a caller
    /// bug), so it escaped untyped from an API contracted to return typed results. Eviction had always
    /// respected <c>InUse</c>; disposal had not.</para>
    ///
    /// <para>Handing over rather than waiting is deliberate: draining would make shutdown block on
    /// however long a remote command takes, and a bounded drain would just make the same race rarer
    /// instead of removing it.</para>
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        // Taking _lifetime here is what waits out a sweep that is already in flight. Once this returns,
        // no evictor is running and none can start, so the gates below are safe to free.
        lock (_lifetime)
        {
            if (_disposed) return;
            _disposed = true;
        }

        _evictionTimer.Dispose();

        foreach (var entry in _entries.Values)
        {
            await entry.Gate.WaitAsync().ConfigureAwait(false);
            var handedOver = false;
            try
            {
                entry.PoolDisposed = true;

                // Still borrowed: the lease owns the teardown now. Its gate has to outlive this loop,
                // or returning it would fault on a disposed semaphore — the same escape by a new route.
                if (entry.InUse != 0)
                {
                    handedOver = true;
                }
                else
                {
                    entry.Session?.Dispose();
                    entry.Session = null;
                }
            }
            finally
            {
                entry.Gate.Release();
                if (!handedOver) entry.Gate.Dispose();
            }
        }

        _entries.Clear();
    }

    // Carries the TimeProvider so a returning lease stamps LastUsed from the same clock the evictor
    // reads. Mixing the injected clock with DateTimeOffset.UtcNow here would make a FakeTimeProvider
    // test pass or fail on wall-clock timing, which is the flakiness the injection exists to remove.
    internal sealed class PoolEntry(TimeProvider time)
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public ISshSession? Session { get; set; }
        public int InUse { get; set; }
        public TimeProvider Time => time;
        public DateTimeOffset LastUsed { get; set; } = time.GetUtcNow();

        /// <summary>
        /// Set once the pool has been disposed while this entry was still borrowed. The last lease to
        /// return then owns disposing the session and this entry's gate. Written and read only under
        /// <see cref="Gate"/>.
        /// </summary>
        public bool PoolDisposed { get; set; }
    }

    /// <summary>A borrowed reference to a shared pooled session. Disposing returns it (does not close it).</summary>
    internal sealed class PooledSessionLease(PoolEntry entry, ISshSession session) : IDisposable
    {
        private int _returned;
        public ISshSession Session => session;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _returned, 1) != 0)
                return;

            var tearDown = false;
            entry.Gate.Wait();
            try
            {
                entry.InUse--;
                entry.LastUsed = entry.Time.GetUtcNow();

                // The pool went away while this operation was running, and this is the last borrower
                // out — so closing the transport is now this lease's job. Without it a disposed pool
                // would leak an authenticated session for the lifetime of the process.
                if (entry.PoolDisposed && entry.InUse == 0)
                {
                    entry.Session?.Dispose();
                    entry.Session = null;
                    tearDown = true;
                }
            }
            finally
            {
                entry.Gate.Release();
                if (tearDown) entry.Gate.Dispose();
            }
        }
    }
}
