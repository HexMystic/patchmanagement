using System.Diagnostics;
using Microsoft.Extensions.Logging;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.DoubleHop;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.WinRm;

/// <summary>
/// WinRM implementation of <see cref="IEndpointConnector"/> for Windows endpoints (WinRM/HTTPS +
/// PowerShell Remoting). Structurally identical to <see cref="SshConnector"/>: every operation takes
/// a concurrency lease, honours an explicit timeout, and serialises same-key retries for idempotency
/// (NEVER #5). Credentials are resolved through the Phase-1 <see cref="ICredentialProvider"/> and used
/// in memory only (NEVER #1/#2).
///
/// The double-hop problem lives here (HARD-PROBLEMS #9): a command that must authenticate onward to
/// an SMB share/another session is <b>surfaced</b> as <see cref="ConnectorOutcome.DoubleHopRequired"/>
/// rather than hung, unless the target explicitly enables scoped delegation.
/// </summary>
public sealed class WinRmConnector : IEndpointConnector
{
    private readonly ICredentialProvider _credentials;
    private readonly IWinRmClient _client;
    private readonly IConnectionGovernor _governor;
    private readonly IOperationCoordinator _operations;
    private readonly ILogger<WinRmConnector> _logger;

    internal WinRmConnector(
        ICredentialProvider credentials,
        IWinRmClient client,
        IConnectionGovernor governor,
        IOperationCoordinator operations,
        ILogger<WinRmConnector> logger)
    {
        _credentials = credentials;
        _client = client;
        _governor = governor;
        _operations = operations;
        _logger = logger;
    }

    public EndpointProtocol Protocol => EndpointProtocol.WinRm;

    public async Task<ConnectivityResult> TestConnectivityAsync(EndpointTarget target, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        var sw = Stopwatch.StartNew();
        await using var lease = await _governor.AcquireAsync(target.TenantId, ConnectionKey.HostKeyFor(ConnectionPlanner.Plan(target)), ct).ConfigureAwait(false);
        try
        {
            using var credential = await _credentials.ResolveAsync(target.Credential, ct).ConfigureAwait(false);
            await _client.ProbeAsync(target, credential, TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
            return ConnectivityResult.Reachable(sw.Elapsed);
        }
        catch (ConnectorConnectException ex)
        {
            _logger.LogInformation("WinRM connectivity probe to {Asset} failed: {Outcome}", target.AssetId ?? target.Host, ex.Outcome);
            return ConnectivityResult.Failed(ex.Outcome, ex.Message, sw.Elapsed);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ConnectivityResult.Failed(ConnectorOutcome.Timeout, "Connectivity probe timed out.", sw.Elapsed);
        }
    }

    public async Task<CommandResult> RunAsync(EndpointTarget target, RemoteCommand command, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(command);
        RequirePositiveTimeout(command.Timeout);

        var hop = DoubleHopDetector.Assess(command, EndpointProtocol.WinRm);
        if (hop.RequiresOnwardAuth && !target.AllowCredentialDelegation)
            return CommandResult.Failed(ConnectorOutcome.DoubleHopRequired, DoubleHopMessage(hop), TimeSpan.Zero);

        var sw = Stopwatch.StartNew();
        await using var op = await _operations.AcquireAsync(command.IdempotencyKey, ct).ConfigureAwait(false);
        await using var lease = await _governor.AcquireAsync(target.TenantId, ConnectionKey.HostKeyFor(ConnectionPlanner.Plan(target)), ct).ConfigureAwait(false);
        try
        {
            using var credential = await _credentials.ResolveAsync(target.Credential, ct).ConfigureAwait(false);
            return await _client.ExecuteAsync(target, credential, command.CommandLine, command.Timeout, ct).ConfigureAwait(false);
        }
        catch (ConnectorConnectException ex)
        {
            return CommandResult.Failed(ex.Outcome, ex.Message, sw.Elapsed);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return CommandResult.Failed(ConnectorOutcome.Timeout, "Command timed out.", sw.Elapsed);
        }
    }

    public Task<FileResult> PushAsync(EndpointTarget target, FileTransfer file, CancellationToken ct) =>
        TransferAsync(target, file, push: true, ct);

    public Task<FileResult> PullAsync(EndpointTarget target, FileTransfer file, CancellationToken ct) =>
        TransferAsync(target, file, push: false, ct);

    private async Task<FileResult> TransferAsync(EndpointTarget target, FileTransfer file, bool push, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(file);
        RequirePositiveTimeout(file.Timeout);

        // Transfers were never assessed, yet writing to \\server\share over a WinRM session is the
        // textbook double-hop — the exact case HARD-PROBLEMS #9 opens with.
        var transferHop = DoubleHopDetector.Assess(file, EndpointProtocol.WinRm);
        if (transferHop.RequiresOnwardAuth && !target.AllowCredentialDelegation)
        {
            return FileResult.Failed(
                ConnectorOutcome.DoubleHopRequired, file.RemotePath, DoubleHopMessage(transferHop), TimeSpan.Zero);
        }

        var sw = Stopwatch.StartNew();
        await using var op = await _operations.AcquireAsync(file.IdempotencyKey, ct).ConfigureAwait(false);
        await using var lease = await _governor.AcquireAsync(target.TenantId, ConnectionKey.HostKeyFor(ConnectionPlanner.Plan(target)), ct).ConfigureAwait(false);
        try
        {
            using var credential = await _credentials.ResolveAsync(target.Credential, ct).ConfigureAwait(false);
            if (push)
            {
                var written = await _client.UploadAsync(target, credential, file, ct).ConfigureAwait(false);
                return FileResult.Ok(file.RemotePath, written, sw.Elapsed);
            }

            using var buffer = new MemoryStream();
            var read = await _client.DownloadAsync(target, credential, file, buffer, ct).ConfigureAwait(false);
            var bytes = buffer.ToArray();
            if (file.LocalPath is { } localPath)
                await File.WriteAllBytesAsync(localPath, bytes, ct).ConfigureAwait(false);
            return FileResult.Ok(file.RemotePath, read, sw.Elapsed, bytes);
        }
        catch (ConnectorConnectException ex)
        {
            return FileResult.Failed(ex.Outcome, file.RemotePath, ex.Message, sw.Elapsed);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return FileResult.Failed(ConnectorOutcome.Timeout, file.RemotePath, "Transfer timed out.", sw.Elapsed);
        }
    }

    private static void RequirePositiveTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(timeout), timeout, "Every remote operation must be time-bounded (CLAUDE.md NEVER #5).");
    }

    private static string DoubleHopMessage(DoubleHopAssessment hop) =>
        $"Double-hop required and credential delegation is not enabled for this target: {hop.Reason} " +
        "Push the payload to the target first and run it locally (recommended), or enable scoped delegation.";
}
