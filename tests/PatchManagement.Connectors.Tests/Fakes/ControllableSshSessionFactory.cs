using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// A session factory that records how many operations were in flight <b>at once</b>.
///
/// <para><b>Operations, not sessions — and the distinction is the whole trap.</b> A pooled session
/// deliberately outlives the operation that created it; that is what pooling is for. So counting
/// live sessions in a pooling connector counts every session ever created, which for twelve distinct
/// hosts is twelve regardless of how strictly concurrency is capped. The budget the governor
/// enforces is on work in flight, so that is what this measures: enter and exit around each
/// operation, not around construction and disposal.</para>
///
/// <para><see cref="PeakConcurrentOperations"/> is a high-water mark rather than a sampled count.
/// Asserting a cap by timing — start N, sleep, look — measures the scheduler as much as the
/// governor. A high-water mark records the maximum overlap that actually occurred, so the assertion
/// is about something that has already happened.</para>
/// </summary>
internal sealed class ControllableSshSessionFactory : ISshSessionFactory
{
    private readonly Func<ISshSession> _create;
    private readonly object _sync = new();
    private readonly List<(int Count, TaskCompletionSource Signal)> _watchers = [];
    private int _inFlight;

    public ControllableSshSessionFactory(Func<ISshSession>? create = null) =>
        _create = create ?? (() => new RecordingSshSession());

    /// <summary>Sessions constructed. Rises to one per distinct connection key, pooling notwithstanding.</summary>
    public int TotalSessionsCreated { get; private set; }

    /// <summary>Operations begun across all sessions.</summary>
    public int OperationsStarted { get; private set; }

    /// <summary>The most operations ever in flight simultaneously — what the governor caps.</summary>
    public int PeakConcurrentOperations { get; private set; }

    /// <summary>Completes once <paramref name="count"/> operations have begun. A fact, not a duration.</summary>
    public Task OperationsReach(int count)
    {
        lock (_sync)
        {
            if (OperationsStarted >= count) return Task.CompletedTask;

            var signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _watchers.Add((count, signal));
            return signal.Task;
        }
    }

    public async Task<ISshSession> ConnectAsync(
        ConnectionPlan plan, CredentialResolver resolve, TimeSpan connectTimeout, CancellationToken ct)
    {
        using (var credential = await resolve(plan.Destination.Credential, ct).ConfigureAwait(false))
        {
            // Resolved and disposed as the real factory does, so credential-lifecycle assertions
            // stay meaningful when a test uses this factory.
        }

        lock (_sync) TotalSessionsCreated++;
        return new TrackedSession(_create(), this);
    }

    private void OperationStarted()
    {
        List<TaskCompletionSource> ready = [];
        lock (_sync)
        {
            _inFlight++;
            OperationsStarted++;
            if (_inFlight > PeakConcurrentOperations) PeakConcurrentOperations = _inFlight;

            foreach (var watcher in _watchers.Where(w => OperationsStarted >= w.Count).ToList())
            {
                ready.Add(watcher.Signal);
                _watchers.Remove(watcher);
            }
        }

        // Completed outside the lock: an inline continuation could re-enter this factory.
        foreach (var signal in ready) signal.TrySetResult();
    }

    private void OperationEnded()
    {
        lock (_sync) _inFlight--;
    }

    /// <summary>Wraps a session so each operation is bracketed by the concurrency accounting.</summary>
    private sealed class TrackedSession(ISshSession inner, ControllableSshSessionFactory owner) : ISshSession
    {
        public bool IsConnected => inner.IsConnected;

        public async Task<CommandResult> RunAsync(
            string commandLine, TimeSpan timeout, ReadOnlyMemory<byte> stdin, CancellationToken ct)
        {
            owner.OperationStarted();
            try { return await inner.RunAsync(commandLine, timeout, stdin, ct).ConfigureAwait(false); }
            finally { owner.OperationEnded(); }
        }

        public async Task<long> UploadAsync(Stream content, string remotePath, TimeSpan timeout, CancellationToken ct)
        {
            owner.OperationStarted();
            try { return await inner.UploadAsync(content, remotePath, timeout, ct).ConfigureAwait(false); }
            finally { owner.OperationEnded(); }
        }

        public async Task<long> DownloadAsync(string remotePath, Stream destination, TimeSpan timeout, CancellationToken ct)
        {
            owner.OperationStarted();
            try { return await inner.DownloadAsync(remotePath, destination, timeout, ct).ConfigureAwait(false); }
            finally { owner.OperationEnded(); }
        }

        public void Dispose() => inner.Dispose();
    }
}
