using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Options;

namespace PatchManagement.Connectors.Concurrency;

/// <summary>
/// In-process <see cref="IConnectionGovernor"/> backed by semaphores: a global cap, a cap per tenant,
/// and a cap per host.
///
/// <para><b>Acquisition order is tenant, then host, then global</b>, released in reverse. The order is
/// a deliberate fairness decision, not an arbitrary one. Taking the global permit FIRST — as this
/// originally did — means a tenant already at its own ceiling still consumes a global permit while it
/// waits, so one busy tenant can drain the global budget and starve every other tenant out of a
/// resource none of them is over-using. Taking the tenant permit first makes a saturated tenant block
/// on its own semaphore while holding nothing shared. A single consistent order across all callers is
/// what keeps three nested semaphores deadlock-free.</para>
///
/// <para>Production replaces this with a Redis-backed limiter behind
/// <see cref="IConnectionGovernor"/> to share the budget across API nodes; nothing that depends on
/// the interface changes.</para>
/// </summary>
internal sealed class SemaphoreConnectionGovernor : IConnectionGovernor, IDisposable
{
    private readonly ConnectorConcurrencyOptions _options;
    private readonly ConnectorMetrics _metrics;
    private readonly SemaphoreSlim _global;
    private readonly ConcurrentDictionary<Guid, Slot> _tenants = new();
    private readonly ConcurrentDictionary<string, Slot> _hosts = new(StringComparer.Ordinal);

    // Guards the rent/return bookkeeping so a slot is never pruned while someone still needs it.
    // Waiting happens on the semaphores OUTSIDE this lock; only the counters are serialised.
    private readonly object _sync = new();

    private int _activeGlobal;
    private int _waitingGlobal;
    private bool _disposed;

    /// <summary>
    /// <paramref name="meterName"/> is a test seam — see <see cref="ConnectorMetrics"/>. Production
    /// leaves it null and publishes under the well-known meter name.
    /// </summary>
    public SemaphoreConnectionGovernor(
        IOptions<ConnectorConcurrencyOptions> options, string? meterName = null)
    {
        _options = options.Value;
        _options.Validate();
        _metrics = new ConnectorMetrics(meterName);
        _global = new SemaphoreSlim(_options.GlobalMaxConnections, _options.GlobalMaxConnections);
    }

    public int ActiveGlobal => Volatile.Read(ref _activeGlobal);
    public int WaitingGlobal => Volatile.Read(ref _waitingGlobal);
    public int AvailableGlobal => _global.CurrentCount;

    public int ActiveForTenant(Guid tenantId) =>
        _tenants.TryGetValue(tenantId, out var slot) ? slot.Active : 0;

    public int ActiveForHost(string hostKey) =>
        _hosts.TryGetValue(hostKey, out var slot) ? slot.Active : 0;

    public int WaitingForTenant(Guid tenantId) =>
        _tenants.TryGetValue(tenantId, out var slot) ? slot.Waiting : 0;

    /// <summary>Test seam: how many per-tenant/per-host slots are currently retained.</summary>
    internal int TrackedSlotCount => _tenants.Count + _hosts.Count;

    /// <summary>
    /// Test seam, raised once an operation has been counted as waiting and is about to block.
    ///
    /// <para>It exists so concurrency tests can be deterministic instead of timing-based. Without it
    /// a test asserting "the third operation is queued" has to sleep and hope, which is how
    /// concurrency suites become the ones everybody reruns until they go green. The counters are
    /// already incremented when this fires and the permits are already exhausted, so the observation
    /// is stable rather than a snapshot of a race.</para>
    /// </summary>
    internal event Action? WaiterRegistered;

    public async Task<IConnectionLease> AcquireAsync(Guid tenantId, string hostKey, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(hostKey);

        var tenant = Rent(_tenants, tenantId, _options.PerTenantMaxConnections);
        var host = Rent(_hosts, hostKey, _options.PerHostMaxConnections);

        var stopwatch = Stopwatch.StartNew();
        var tenantHeld = false;
        var hostHeld = false;
        var globalHeld = false;

        Interlocked.Increment(ref tenant.WaitingCount);
        Interlocked.Increment(ref _waitingGlobal);
        _metrics.WaitStarted();
        WaiterRegistered?.Invoke();
        try
        {
            await tenant.Semaphore.WaitAsync(ct).ConfigureAwait(false);
            tenantHeld = true;
            await host.Semaphore.WaitAsync(ct).ConfigureAwait(false);
            hostHeld = true;
            await _global.WaitAsync(ct).ConfigureAwait(false);
            globalHeld = true;
        }
        catch
        {
            // Unwind whatever was taken, in reverse, so a cancellation cannot leak a permit. A leaked
            // permit is invisible until the budget is exhausted and the process quietly stops
            // connecting, with the cause hours of log-reading away.
            if (globalHeld) _global.Release();
            if (hostHeld) host.Semaphore.Release();
            if (tenantHeld) tenant.Semaphore.Release();
            Return(_hosts, hostKey, host);
            Return(_tenants, tenantId, tenant);
            throw;
        }
        finally
        {
            // In the finally, so a CANCELLED waiter is removed from the queue depth too. Leaving it
            // counted would make the number a scheduler throttles on drift permanently upward, and
            // the drift is invisible because nothing ever reconciles it.
            Interlocked.Decrement(ref tenant.WaitingCount);
            Interlocked.Decrement(ref _waitingGlobal);
            _metrics.WaitEnded();
        }

        Interlocked.Increment(ref _activeGlobal);
        Interlocked.Increment(ref tenant.ActiveCount);
        Interlocked.Increment(ref host.ActiveCount);
        _metrics.Acquired();
        _metrics.Waited(stopwatch.Elapsed.TotalMilliseconds);

        return new Lease(this, tenantId, hostKey, tenant, host);
    }

    public bool TryAcquire(Guid tenantId, string hostKey, out IConnectionLease? lease)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(hostKey);

        lease = null;
        var tenant = Rent(_tenants, tenantId, _options.PerTenantMaxConnections);
        var host = Rent(_hosts, hostKey, _options.PerHostMaxConnections);

        var tenantHeld = false;
        var hostHeld = false;

        // Same order as the waiting path — mixing orders between the two would reintroduce exactly
        // the deadlock a single consistent ordering exists to prevent.
        tenantHeld = tenant.Semaphore.Wait(0);
        if (!tenantHeld) return Refuse();

        hostHeld = host.Semaphore.Wait(0);
        if (!hostHeld) return Refuse();

        if (!_global.Wait(0)) return Refuse();

        Interlocked.Increment(ref _activeGlobal);
        Interlocked.Increment(ref tenant.ActiveCount);
        Interlocked.Increment(ref host.ActiveCount);
        _metrics.Acquired();

        lease = new Lease(this, tenantId, hostKey, tenant, host);
        return true;

        bool Refuse()
        {
            if (hostHeld) host.Semaphore.Release();
            if (tenantHeld) tenant.Semaphore.Release();
            Return(_hosts, hostKey, host);
            Return(_tenants, tenantId, tenant);
            _metrics.Rejected();
            return false;
        }
    }

    private void Release(Guid tenantId, string hostKey, Slot tenant, Slot host)
    {
        Interlocked.Decrement(ref host.ActiveCount);
        Interlocked.Decrement(ref tenant.ActiveCount);
        Interlocked.Decrement(ref _activeGlobal);

        _global.Release();
        host.Semaphore.Release();
        tenant.Semaphore.Release();

        Return(_hosts, hostKey, host);
        Return(_tenants, tenantId, tenant);
        _metrics.Released();
    }

    /// <summary>
    /// Takes a reference to a slot, creating it on first use. The reference is held for the whole
    /// lease lifetime so <see cref="Return{TKey}"/> can prune safely.
    /// </summary>
    private Slot Rent<TKey>(ConcurrentDictionary<TKey, Slot> map, TKey key, int max) where TKey : notnull
    {
        lock (_sync)
        {
            var slot = map.GetOrAdd(key, _ => new Slot(max));
            slot.References++;
            return slot;
        }
    }

    /// <summary>
    /// Drops a reference and prunes the slot when nobody holds or wants it.
    ///
    /// <para>Without this the dictionaries grew a permanent entry — a <see cref="SemaphoreSlim"/> and
    /// its bookkeeping — for every tenant and every host ever contacted. In a singleton that lives as
    /// long as the process, on a 10,000-endpoint estate, that is an unbounded leak which surfaces as
    /// memory creeping upward with nothing obvious to blame.</para>
    /// </summary>
    private void Return<TKey>(ConcurrentDictionary<TKey, Slot> map, TKey key, Slot slot) where TKey : notnull
    {
        lock (_sync)
        {
            slot.References--;
            if (slot.References > 0 || slot.Active != 0) return;

            // References == 0 under the lock means nobody holds or awaits it, so disposal is safe.
            if (map.TryRemove(key, out _)) slot.Semaphore.Dispose();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _global.Dispose();
        lock (_sync)
        {
            foreach (var slot in _tenants.Values) slot.Semaphore.Dispose();
            foreach (var slot in _hosts.Values) slot.Semaphore.Dispose();
            _tenants.Clear();
            _hosts.Clear();
        }
        _metrics.Dispose();
    }

    private sealed class Slot(int max)
    {
        public SemaphoreSlim Semaphore { get; } = new(max, max);

        // Interlocked targets, so plain fields rather than properties.
        public int ActiveCount;
        public int WaitingCount;

        /// <summary>Holders plus waiters; guarded by the governor's lock rather than Interlocked.</summary>
        public int References;

        public int Active => Volatile.Read(ref ActiveCount);
        public int Waiting => Volatile.Read(ref WaitingCount);
    }

    private sealed class Lease(
        SemaphoreConnectionGovernor owner, Guid tenantId, string hostKey, Slot tenant, Slot host)
        : IConnectionLease
    {
        private int _released;

        public Guid TenantId => tenantId;
        public string HostKey => hostKey;

        public ValueTask DisposeAsync()
        {
            // Idempotent: a double dispose releasing twice would hand back a permit that was never
            // taken, silently raising the ceiling above the configured budget.
            if (Interlocked.Exchange(ref _released, 1) == 0)
                owner.Release(tenantId, hostKey, tenant, host);

            return ValueTask.CompletedTask;
        }
    }
}
