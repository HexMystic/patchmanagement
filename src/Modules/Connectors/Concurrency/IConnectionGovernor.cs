namespace PatchManagement.Connectors.Concurrency;

/// <summary>
/// Governs how many endpoint connections may be open at once — globally, per tenant, and per host.
/// Every connector operation acquires a lease before touching the network and releases it after, so
/// the process can never exceed its configured connection budget (the scaling wall — CLAUDE.md §2).
///
/// <para>The in-process implementation uses semaphores; production swaps in a Redis-backed
/// distributed limiter (backpressure tokens shared across API nodes) behind this same interface —
/// callers are unaware which is wired. That substitution is exactly why the shape here matters: a
/// scheduler throttling 10,000 endpoints can only be as good as what this interface exposes, and
/// widening it later means changing every implementation at once.</para>
///
/// <para><b>Observability is part of the contract, not a debugging aid.</b> Active counts alone
/// cannot distinguish "at capacity, nothing queued" from "at capacity with five thousand operations
/// piled up behind it" — which are the same number and completely different situations. A scheduler
/// deciding whether to admit more work needs the waiting counts and <see cref="TryAcquire"/>; without
/// them its only option is to enqueue blindly and hope.</para>
/// </summary>
public interface IConnectionGovernor
{
    /// <summary>
    /// Acquire a connection lease, waiting until the tenant, host and global budgets all allow it, or
    /// the token is cancelled. Dispose the lease to release every slot it holds.
    /// </summary>
    /// <param name="hostKey">
    /// The host dimension, from <c>ConnectionKey.HostKeyFor</c>. Shared across tenants on purpose: a
    /// remote host cares how many sessions it is serving in total, not whose they are.
    /// </param>
    Task<IConnectionLease> AcquireAsync(Guid tenantId, string hostKey, CancellationToken ct);

    /// <summary>
    /// Take a lease only if one is free right now. Returns false rather than queueing, so a caller
    /// can shed load or pick a different target instead of committing to an unbounded wait.
    /// </summary>
    bool TryAcquire(Guid tenantId, string hostKey, out IConnectionLease? lease);

    /// <summary>Held leases across all tenants.</summary>
    int ActiveGlobal { get; }

    /// <summary>Held leases for one tenant.</summary>
    int ActiveForTenant(Guid tenantId);

    /// <summary>Held leases against one host, summed across tenants.</summary>
    int ActiveForHost(string hostKey);

    /// <summary>Operations blocked waiting for global capacity — the queue depth a scheduler throttles on.</summary>
    int WaitingGlobal { get; }

    /// <summary>Operations blocked waiting for this tenant's capacity.</summary>
    int WaitingForTenant(Guid tenantId);

    /// <summary>Global slots free right now. Zero with a non-zero <see cref="WaitingGlobal"/> means saturation.</summary>
    int AvailableGlobal { get; }
}

/// <summary>A held connection slot. Disposing releases the tenant, host and global budgets.</summary>
public interface IConnectionLease : IAsyncDisposable
{
    Guid TenantId { get; }

    /// <summary>The host dimension this lease was taken against.</summary>
    string HostKey { get; }
}
