using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// A session whose operations block until the test releases them or the token fires — the stand-in
/// for a remote host that has accepted the work and gone quiet.
///
/// <para><see cref="Entered"/> is the whole point. A cancellation test that cancels on a timer is
/// really asserting that the machine scheduled two threads in the expected order, which is why such
/// tests fail on a loaded CI box and get "fixed" with longer sleeps until they assert nothing.
/// Awaiting <see cref="Entered"/> makes "the operation is now in flight" an observed fact.</para>
///
/// <para>Modelled on the vault suite's <c>StallingKeyProvider</c>, which exists for the same reason.</para>
/// </summary>
internal sealed class StallingSshSession : ISshSession
{
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release;

    /// <param name="release">
    /// An optional gate SHARED with other sessions. Sharing one gate matters when the sessions are
    /// created progressively — as they are when a concurrency budget admits work in waves — because
    /// a test that only releases the sessions it can see at one instant will hang on the ones created
    /// afterwards.
    /// </param>
    public StallingSshSession(TaskCompletionSource? release = null) =>
        _release = release ?? new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

    public bool IsConnected { get; private set; } = true;
    public bool Disposed { get; private set; }

    /// <summary>Completes once an operation has actually begun.</summary>
    public Task Entered => _entered.Task;

    /// <summary>Lets a stalled operation finish, for tests that need it to complete rather than fail.</summary>
    public void Release() => _release.TrySetResult();

    public async Task<CommandResult> RunAsync(
        string commandLine, TimeSpan timeout, ReadOnlyMemory<byte> stdin, CancellationToken ct)
    {
        await StallAsync(ct).ConfigureAwait(false);
        return CommandResult.Ran(0, "released", string.Empty, TimeSpan.Zero);
    }

    public async Task<long> UploadAsync(Stream content, string remotePath, TimeSpan timeout, CancellationToken ct)
    {
        await StallAsync(ct).ConfigureAwait(false);
        return 0;
    }

    public async Task<long> DownloadAsync(string remotePath, Stream destination, TimeSpan timeout, CancellationToken ct)
    {
        await StallAsync(ct).ConfigureAwait(false);
        return 0;
    }

    private async Task StallAsync(CancellationToken ct)
    {
        _entered.TrySetResult();

        // Completes on release, or throws on cancellation — exactly what a real transport does when
        // its token fires mid-operation.
        var cancelled = new TaskCompletionSource();
        await using var registration = ct.Register(() => cancelled.TrySetCanceled(ct));

        await await Task.WhenAny(_release.Task, cancelled.Task).ConfigureAwait(false);
    }

    public void Dispose()
    {
        Disposed = true;
        IsConnected = false;
        _release.TrySetResult(); // never leave a stalled awaiter hanging when the session goes away
    }
}
