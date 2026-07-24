using System.Collections.Concurrent;

namespace PatchManagement.Connectors.Concurrency;

/// <summary>
/// In-process <see cref="IOperationCoordinator"/>: a reference-counted <see cref="SemaphoreSlim"/>
/// per key. The semaphore is created on first use and removed once no waiter/holder remains, so the
/// map does not grow without bound. Serialises same-key operations for idempotency.
/// </summary>
internal sealed class KeyedOperationCoordinator : IOperationCoordinator
{
    private readonly ConcurrentDictionary<string, Entry> _locks = new(StringComparer.Ordinal);

    public async Task<IAsyncDisposable> AcquireAsync(string? operationKey, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(operationKey))
            return NullHandle.Instance;

        var entry = _locks.AddOrUpdate(
            operationKey,
            _ => new Entry(),
            (_, existing) => { existing.AddRef(); return existing; });

        try
        {
            await entry.Semaphore.WaitAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            ReleaseRef(operationKey, entry, enteredSemaphore: false);
            throw;
        }

        return new Handle(this, operationKey, entry);
    }

    private void ReleaseRef(string key, Entry entry, bool enteredSemaphore)
    {
        if (enteredSemaphore)
            entry.Semaphore.Release();

        if (entry.Release() == 0)
        {
            // Last reference: remove only if it is still the same entry (avoid racing a new one).
            if (_locks.TryGetValue(key, out var current) && ReferenceEquals(current, entry))
                ((ICollection<KeyValuePair<string, Entry>>)_locks)
                    .Remove(new KeyValuePair<string, Entry>(key, entry));
        }
    }

    private sealed class Entry
    {
        public SemaphoreSlim Semaphore { get; } = new(1, 1);
        private int _refCount = 1;
        public void AddRef() => Interlocked.Increment(ref _refCount);
        public int Release() => Interlocked.Decrement(ref _refCount);
    }

    private sealed class Handle(KeyedOperationCoordinator owner, string key, Entry entry) : IAsyncDisposable
    {
        private int _disposed;

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                owner.ReleaseRef(key, entry, enteredSemaphore: true);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class NullHandle : IAsyncDisposable
    {
        public static readonly NullHandle Instance = new();
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
