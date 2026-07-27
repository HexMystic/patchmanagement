using System.Diagnostics;
using PatchManagement.Contracts.Connectors;
using Renci.SshNet;

namespace PatchManagement.Connectors.Ssh;

/// <summary>
/// Real <see cref="ISshSession"/> over SSH.NET. Commands run on multiplexed channels of one SSH
/// transport; SFTP is used for transfers. Every call is bounded by a linked cancellation token that
/// fires at the supplied timeout, so a hung remote never blocks forever (NEVER #5).
///
/// May own bastion resources (a jump-host client + local port-forward) that are disposed with the
/// session — the caller cannot tell a tunnelled session from a direct one (ADR 0003).
/// </summary>
internal sealed class SshNetSession : ISshSession
{
    private readonly SshClient _client;
    private readonly ConnectionInfo _effectiveConnectionInfo;
    private readonly IDisposable[] _ownedResources;
    private SftpClient? _sftp;
    private bool _disposed;

    public SshNetSession(SshClient client, ConnectionInfo effectiveConnectionInfo, params IDisposable[] ownedResources)
    {
        _client = client;
        _effectiveConnectionInfo = effectiveConnectionInfo;
        _ownedResources = ownedResources;
    }

    public bool IsConnected => !_disposed && _client.IsConnected;

    public async Task<CommandResult> RunAsync(
        string commandLine, TimeSpan timeout, ReadOnlyMemory<byte> stdin, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        using var cmd = _client.CreateCommand(commandLine);
        cmd.CommandTimeout = timeout;
        try
        {
            // Write stdin BEFORE executing and close it, so a command that blocks reading input
            // (sudo -S waiting on a password) is never deadlocked against a stream we never wrote.
            if (!stdin.IsEmpty)
            {
                var input = cmd.CreateInputStream();
                await input.WriteAsync(stdin, cts.Token).ConfigureAwait(false);
                await input.FlushAsync(cts.Token).ConfigureAwait(false);
                // Closing signals EOF; without it sudo waits for more input until the timeout.
                await input.DisposeAsync().ConfigureAwait(false);
            }

            // SSH.NET 2025.1.0: ExecuteAsync returns a bare Task — stdout is read from Result
            // once the command has completed, not from the awaited value.
            await cmd.ExecuteAsync(cts.Token).ConfigureAwait(false);
            return CommandResult.Ran(cmd.ExitStatus ?? -1, cmd.Result ?? string.Empty, cmd.Error ?? string.Empty, sw.Elapsed);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            TryCancel(cmd);
            return CommandResult.Failed(ConnectorOutcome.Timeout, "Command exceeded its time budget and was cancelled.", sw.Elapsed);
        }
    }

    public async Task<long> UploadAsync(Stream content, string remotePath, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var sftp = await EnsureSftpAsync(cts.Token).ConfigureAwait(false);

        await using var remote = sftp.Create(remotePath);
        var written = await CopyCountingAsync(content, remote, cts.Token).ConfigureAwait(false);
        await remote.FlushAsync(cts.Token).ConfigureAwait(false);
        return written;
    }

    public async Task<long> DownloadAsync(string remotePath, Stream destination, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var sftp = await EnsureSftpAsync(cts.Token).ConfigureAwait(false);

        await using var remote = sftp.OpenRead(remotePath);
        return await CopyCountingAsync(remote, destination, cts.Token).ConfigureAwait(false);
    }

    private async Task<SftpClient> EnsureSftpAsync(CancellationToken ct)
    {
        if (_sftp is { IsConnected: true })
            return _sftp;

        _sftp?.Dispose();
        _sftp = new SftpClient(_effectiveConnectionInfo);
        await _sftp.ConnectAsync(ct).ConfigureAwait(false);
        return _sftp;
    }

    private static async Task<long> CopyCountingAsync(Stream source, Stream destination, CancellationToken ct)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            await destination.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            total += read;
        }
        return total;
    }

    private static void TryCancel(SshCommand cmd)
    {
        try { cmd.CancelAsync(forceKill: true, millisecondsTimeout: 500); }
        catch { /* best-effort: the linked token already unblocked us */ }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        SafeDispose(_sftp);
        SafeDispose(_client);
        foreach (var resource in _ownedResources)
            SafeDispose(resource);
    }

    private static void SafeDispose(IDisposable? d)
    {
        try { d?.Dispose(); }
        catch { /* disposing a broken transport must never throw */ }
    }
}
