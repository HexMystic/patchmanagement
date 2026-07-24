namespace PatchManagement.Connectors.Concurrency;

/// <summary>
/// Governs how many endpoint connections may be open at once — globally and per tenant. Every
/// connector operation acquires a lease before touching the network and releases it after, so the
/// process can never exceed its configured connection budget (the scaling wall — CLAUDE.md §2).
///
/// The in-process implementation uses semaphores; production swaps in a Redis-backed distributed
/// limiter (backpressure tokens shared across API nodes) behind this same interface — callers are
/// unaware which is wired.
/// </summary>
public interface IConnectionGovernor
{
    /// <summary>
    /// Acquire a connection lease for <paramref name="tenantId"/>, waiting (with backpressure)
    /// until both the per-tenant and global budgets allow it, or the token is cancelled.
    /// Dispose the lease to release both slots.
    /// </summary>
    Task<IConnectionLease> AcquireAsync(Guid tenantId, CancellationToken ct);

    /// <summary>Current number of held leases across all tenants (instrumentation).</summary>
    int ActiveGlobal { get; }

    /// <summary>Current number of held leases for a tenant (instrumentation).</summary>
    int ActiveForTenant(Guid tenantId);
}

/// <summary>A held connection slot. Disposing releases the tenant and global budget.</summary>
public interface IConnectionLease : IAsyncDisposable
{
    Guid TenantId { get; }
}
