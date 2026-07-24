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
    /// Acquire the lock for <paramref name="operationKey"/>, waiting until it is free or the token
    /// is cancelled. Dispose the returned handle to release. A null/empty key is a no-op handle.
    /// </summary>
    Task<IAsyncDisposable> AcquireAsync(string? operationKey, CancellationToken ct);
}
