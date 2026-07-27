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
    private bool _disposed;

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
    /// Borrow a shared session for <paramref name="key"/>, creating it via <paramref name="connect"/>
    /// if none is cached or the cached one is dead. Dispose the returned lease when the operation
    /// finishes; the underlying session stays open for reuse.
    /// </summary>
    public async Task<PooledSessionLease> AcquireAsync(
        string key,
        Func<CancellationToken, Task<ISshSession>> connect,
        CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EvictIdle();

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
        var cutoff = _time.GetUtcNow() - _options.PooledSessionIdleTimeout;
        foreach (var (key, entry) in _entries)
        {
            if (entry.InUse != 0 || entry.LastUsed > cutoff)
                continue;

            if (!entry.Gate.Wait(0))
                continue;
            try
            {
                if (entry.InUse == 0 && entry.LastUsed <= cutoff && _entries.TryRemove(key, out _))
                {
                    entry.Session?.Dispose();
                    entry.Session = null;
                }
            }
            finally
            {
                entry.Gate.Release();
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _evictionTimer.Dispose();
        foreach (var entry in _entries.Values)
        {
            await entry.Gate.WaitAsync().ConfigureAwait(false);
            try
            {
                entry.Session?.Dispose();
                entry.Session = null;
            }
            finally
            {
                entry.Gate.Release();
                entry.Gate.Dispose();
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
            entry.Gate.Wait();
            try
            {
                entry.InUse--;
                entry.LastUsed = entry.Time.GetUtcNow();
            }
            finally
            {
                entry.Gate.Release();
            }
        }
    }
}
