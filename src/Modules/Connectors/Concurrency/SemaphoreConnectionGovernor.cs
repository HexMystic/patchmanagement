using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace PatchManagement.Connectors.Concurrency;

/// <summary>
/// In-process <see cref="IConnectionGovernor"/> backed by semaphores: one global cap plus one cap
/// per tenant. Acquisition order is always <b>global then tenant</b> and release is the reverse, so
/// the two levels can never deadlock. Live counts are exposed for instrumentation.
///
/// This is a real, bounded pool of permits — not a placeholder. Production replaces it with a
/// Redis-backed limiter behind <see cref="IConnectionGovernor"/> to share the budget across API
/// nodes; nothing that depends on the interface changes.
/// </summary>
internal sealed class SemaphoreConnectionGovernor : IConnectionGovernor, IDisposable
{
    private readonly ConnectorConcurrencyOptions _options;
    private readonly SemaphoreSlim _global;
    private readonly ConcurrentDictionary<Guid, TenantSlot> _tenants = new();
    private int _activeGlobal;

    public SemaphoreConnectionGovernor(IOptions<ConnectorConcurrencyOptions> options)
    {
        _options = options.Value;
        _options.Validate();
        _global = new SemaphoreSlim(_options.GlobalMaxConnections, _options.GlobalMaxConnections);
    }

    public int ActiveGlobal => Volatile.Read(ref _activeGlobal);

    public int ActiveForTenant(Guid tenantId) =>
        _tenants.TryGetValue(tenantId, out var slot) ? slot.Active : 0;

    public async Task<IConnectionLease> AcquireAsync(Guid tenantId, CancellationToken ct)
    {
        var slot = _tenants.GetOrAdd(tenantId, _ => new TenantSlot(_options.PerTenantMaxConnections));

        // Global first so a saturated global budget applies backpressure before we reserve a
        // tenant slot; release is strictly reverse order.
        await _global.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await slot.Semaphore.WaitAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            _global.Release();
            throw;
        }

        Interlocked.Increment(ref _activeGlobal);
        slot.Increment();
        return new Lease(this, tenantId, slot);
    }

    private void Release(TenantSlot slot)
    {
        slot.Decrement();
        slot.Semaphore.Release();
        Interlocked.Decrement(ref _activeGlobal);
        _global.Release();
    }

    public void Dispose()
    {
        _global.Dispose();
        foreach (var slot in _tenants.Values)
            slot.Semaphore.Dispose();
    }

    private sealed class TenantSlot(int max)
    {
        private int _active;
        public SemaphoreSlim Semaphore { get; } = new(max, max);
        public int Active => Volatile.Read(ref _active);
        public void Increment() => Interlocked.Increment(ref _active);
        public void Decrement() => Interlocked.Decrement(ref _active);
    }

    private sealed class Lease(SemaphoreConnectionGovernor owner, Guid tenantId, TenantSlot slot) : IConnectionLease
    {
        private int _released;
        public Guid TenantId => tenantId;

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
                owner.Release(slot);
            return ValueTask.CompletedTask;
        }
    }
}
