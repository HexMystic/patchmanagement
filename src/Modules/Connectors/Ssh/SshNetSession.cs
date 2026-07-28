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
            // Execution must be UNDER WAY before an input stream exists.
            //
            // SSH.NET 2025.1.0 refuses CreateInputStream() outside execution — "The input stream can
            // be used only during execution." — because the stream writes to a channel that does not
            // exist until the command is started. This previously wrote stdin FIRST, so every
            // elevated command carrying a sudo password threw InvalidOperationException out of the
            // connector. Nothing caught it: the unit suite stops at RecordingSshSession, and the lab
            // fleet is NOPASSWD so no fleet test ever supplied a privilege credential, leaving stdin
            // empty and this branch unentered. See SshStdinTests.
            //
            // ExecuteAsync returns a bare Task; stdout is read from cmd.Result once it completes, not
            // from the awaited value. It is deliberately not awaited yet — the write has to land
            // while the command is running.
            var execution = cmd.ExecuteAsync(cts.Token);

            if (!stdin.IsEmpty)
            {
                try
                {
                    var input = cmd.CreateInputStream();
                    await using (input.ConfigureAwait(false))
                    {
                        await input.WriteAsync(stdin, cts.Token).ConfigureAwait(false);
                        await input.FlushAsync(cts.Token).ConfigureAwait(false);
                    }
                    // Disposing the stream signals EOF. Without it sudo -S waits for more input until
                    // the budget expires, which is a timeout reported for a command that already had
                    // everything it needed.
                }
                catch
                {
                    // The command is already running on the wire. Cancel it before observing, or the
                    // observation blocks on a process still waiting for stdin that will never arrive;
                    // and observe it, or its fault surfaces later as an unobserved-task event with no
                    // context attached to it.
                    TryCancel(cmd);
                    await Observe(execution).ConfigureAwait(false);
                    throw;
                }
            }

            await execution.ConfigureAwait(false);
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

    /// <summary>
    /// Awaits a task purely so its outcome is observed. The caller is already reporting a different
    /// and more informative failure, so whatever this task carries is deliberately dropped.
    /// </summary>
    private static async Task Observe(Task task)
    {
        try { await task.ConfigureAwait(false); }
        catch { /* the original failure is the one worth surfacing */ }
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
