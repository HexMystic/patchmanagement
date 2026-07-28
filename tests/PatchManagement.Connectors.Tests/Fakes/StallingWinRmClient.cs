using PatchManagement.Connectors.WinRm;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// An <see cref="IWinRmClient"/> that accepts every operation and then never finishes, ignoring the
/// timeout it was handed and honouring only the token.
///
/// <para>That is the point: it models an implementation of this seam that mishandles its own budget.
/// <see cref="HttpWinRmClient"/> does bound its receive loop, so a fake that respected timeouts would
/// prove only that the client works — never that the CONNECTOR would survive one that does not. The
/// WinRM path has never run against a real host (D-303), which is precisely why the layer above it
/// must not assume good behaviour below.</para>
/// </summary>
internal sealed class StallingWinRmClient : IWinRmClient
{
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes once an operation has actually begun — an observed fact, not a sleep.</summary>
    public Task Entered => _entered.Task;

    public Task ProbeAsync(EndpointTarget target, ResolvedCredential credential, TimeSpan timeout, CancellationToken ct) =>
        StallAsync(ct);

    public async Task<CommandResult> ExecuteAsync(
        EndpointTarget target, ResolvedCredential credential, string command, TimeSpan timeout, CancellationToken ct)
    {
        await StallAsync(ct).ConfigureAwait(false);
        return CommandResult.Ran(0, "released", string.Empty, TimeSpan.Zero);
    }

    public async Task<long> UploadAsync(
        EndpointTarget target, ResolvedCredential credential, FileTransfer file, CancellationToken ct)
    {
        await StallAsync(ct).ConfigureAwait(false);
        return 0;
    }

    public async Task<long> DownloadAsync(
        EndpointTarget target, ResolvedCredential credential, FileTransfer file, Stream destination, CancellationToken ct)
    {
        await StallAsync(ct).ConfigureAwait(false);
        return 0;
    }

    private async Task StallAsync(CancellationToken ct)
    {
        _entered.TrySetResult();

        var cancelled = new TaskCompletionSource();
        await using var registration = ct.Register(() => cancelled.TrySetCanceled(ct));

        await cancelled.Task.ConfigureAwait(false);
    }
}
