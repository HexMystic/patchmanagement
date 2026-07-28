namespace PatchManagement.Connectors.Concurrency;

/// <summary>
/// Guards idempotency by ensuring the same logical operation key is never executed concurrently
/// (HARD-PROBLEMS #6): a retry that arrives while the original is still running is serialised
/// behind it rather than double-applied. Operations without a key are not coordinated.
///
/// The in-process implementation uses keyed locks; production swaps in a Redis lease (with an
/// expiry so a crashed holder cannot wedge the key) behind this same interface.
/// </summary>
public interface IOperationCoordinator
{
    /// <summary>
    /// Acquire the lock for <paramref name="operationKey"/> <b>within
    /// <paramref name="tenantId"/></b>, waiting until it is free or the token is cancelled. Dispose
    /// the returned handle to release. A null/empty key is a no-op handle.
    ///
    /// <para><b>The tenant is a parameter rather than something the caller folds into the key, and
    /// that is deliberate.</b> This is a process-wide singleton and it used to take the caller's key
    /// verbatim, so two tenants issuing the same key — and the keys are predictable, being derived
    /// from paths and patch ids that every tenant shares the shape of — serialised against each other.
    /// One tenant could stall another's deployments indefinitely just by holding one. Isolation that
    /// depends on callers remembering to prefix is not isolation; requiring the tenant here makes
    /// omitting it a compile error, which is the same reasoning that put the tenant into
    /// <see cref="Connection.ConnectionKey"/>.</para>
    /// </summary>
    Task<IAsyncDisposable> AcquireAsync(Guid tenantId, string? operationKey, CancellationToken ct);
}
