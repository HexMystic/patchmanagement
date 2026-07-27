using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.DoubleHop;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Ssh;

/// <summary>
/// SSH implementation of <see cref="IEndpointConnector"/>. Agentless (CLAUDE.md §2): key-based auth,
/// <c>sudo -n</c> for privileged ops, SFTP for transfers. Every operation is time-bounded and
/// idempotent (NEVER #5): a connection lease from the <see cref="IConnectionGovernor"/> caps
/// concurrency, an <see cref="IOperationCoordinator"/> serialises same-key retries, and the
/// <see cref="ISshSession"/> enforces per-call timeouts so nothing waits forever.
///
/// Credentials are resolved lazily through the Phase-1 <see cref="ICredentialProvider"/> and used in
/// memory only — never logged, cached, or returned (NEVER #1/#2). Provider-neutral: direct vs
/// bastion is chosen by <see cref="ConnectionPlanner"/> from config, with no cloud branch (ADR 0003).
/// </summary>
public sealed class SshConnector : IEndpointConnector
{
    private readonly ICredentialProvider _credentials;
    private readonly ISshSessionFactory _sessionFactory;
    private readonly SshConnectionPool _pool;
    private readonly IConnectionGovernor _governor;
    private readonly IOperationCoordinator _operations;
    private readonly ILogger<SshConnector> _logger;

    internal SshConnector(
        ICredentialProvider credentials,
        ISshSessionFactory sessionFactory,
        SshConnectionPool pool,
        IConnectionGovernor governor,
        IOperationCoordinator operations,
        ILogger<SshConnector> logger)
    {
        _credentials = credentials;
        _sessionFactory = sessionFactory;
        _pool = pool;
        _governor = governor;
        _operations = operations;
        _logger = logger;
    }

    public EndpointProtocol Protocol => EndpointProtocol.Ssh;

    public async Task<ConnectivityResult> TestConnectivityAsync(EndpointTarget target, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        var sw = Stopwatch.StartNew();
        try
        {
            await using var scope = await OpenAsync(target, TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
            // Reaching an authenticated session IS the connectivity+auth proof.
            return ConnectivityResult.Reachable(sw.Elapsed);
        }
        catch (ConnectorConnectException ex)
        {
            _logger.LogInformation("Connectivity probe to {Asset} failed: {Outcome}", target.AssetId ?? target.Host, ex.Outcome);
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

        // Surface a double-hop requirement instead of hanging (HARD-PROBLEMS #9).
        var hop = DoubleHopDetector.Assess(command);
        if (hop.RequiresOnwardAuth && !target.AllowCredentialDelegation)
            return CommandResult.Failed(ConnectorOutcome.DoubleHopRequired, DoubleHopMessage(hop), TimeSpan.Zero);

        var sw = Stopwatch.StartNew();
        await using var op = await _operations.AcquireAsync(command.IdempotencyKey, ct).ConfigureAwait(false);

        // Held outside the try so the finally can wipe it on every exit, including the throwing ones.
        byte[]? elevation = null;
        try
        {
            await using var scope = await OpenAsync(target, command.Timeout, ct).ConfigureAwait(false);

            string line;
            if (command.RequiresElevation && target.PrivilegeCredential is { } privilege)
            {
                elevation = await ReadElevationSecretAsync(privilege, ct).ConfigureAwait(false);
                // -S reads the password from stdin; -p '' suppresses the prompt, which would
                // otherwise land in stdout and pollute the caller's result.
                line = $"sudo -S -p '' {command.CommandLine}";
            }
            else
            {
                // No elevation secret available: -n is non-interactive, so a host that demands a
                // password fails immediately and honestly instead of blocking on a prompt no one
                // can answer (NEVER #5). This is the path the lab exercises — it is NOPASSWD.
                line = command.RequiresElevation ? $"sudo -n {command.CommandLine}" : command.CommandLine;
            }

            return await scope.Session
                .RunAsync(line, command.Timeout, elevation ?? ReadOnlyMemory<byte>.Empty, ct)
                .ConfigureAwait(false);
        }
        catch (ConnectorConnectException ex)
        {
            return CommandResult.Failed(ex.Outcome, ex.Message, sw.Elapsed);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return CommandResult.Failed(ConnectorOutcome.Timeout, "Command timed out.", sw.Elapsed);
        }
        finally
        {
            if (elevation is not null) CryptographicOperations.ZeroMemory(elevation);
        }
    }

    /// <summary>
    /// Resolves the privilege credential into a newline-terminated buffer for <c>sudo -S</c>.
    ///
    /// <para>The copy is deliberate and unavoidable: <see cref="ResolvedCredential.Secret"/> is a
    /// <see cref="ReadOnlySpan{T}"/>, which cannot cross an <c>await</c> — so the bytes must be
    /// materialised synchronously here, before the command runs. The caller owns the result and
    /// zeroes it; this method holds nothing.</para>
    /// </summary>
    private async Task<byte[]> ReadElevationSecretAsync(CredentialRef reference, CancellationToken ct)
    {
        using var credential = await _credentials.ResolveAsync(reference, ct).ConfigureAwait(false);

        var buffer = new byte[credential.Secret.Length + 1];
        credential.Secret.CopyTo(buffer);
        buffer[^1] = (byte)'\n'; // sudo -S expects the password terminated by a newline
        return buffer;
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

        var sw = Stopwatch.StartNew();
        await using var op = await _operations.AcquireAsync(file.IdempotencyKey, ct).ConfigureAwait(false);
        try
        {
            await using var scope = await OpenAsync(target, file.Timeout, ct).ConfigureAwait(false);
            if (push)
            {
                await using var source = OpenPushSource(file);
                var written = await scope.Session.UploadAsync(source, file.RemotePath, file.Timeout, ct).ConfigureAwait(false);
                return FileResult.Ok(file.RemotePath, written, sw.Elapsed);
            }
            else
            {
                using var buffer = new MemoryStream();
                var read = await scope.Session.DownloadAsync(file.RemotePath, buffer, file.Timeout, ct).ConfigureAwait(false);
                var bytes = buffer.ToArray();
                if (file.LocalPath is { } localPath)
                    await File.WriteAllBytesAsync(localPath, bytes, ct).ConfigureAwait(false);
                return FileResult.Ok(file.RemotePath, read, sw.Elapsed, bytes);
            }
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

    private static Stream OpenPushSource(FileTransfer file)
    {
        if (file.Content is { } content)
            return new MemoryStream(content.ToArray(), writable: false);
        if (file.LocalPath is { } path)
            return File.OpenRead(path);
        throw new ArgumentException("A push requires either Content or LocalPath.", nameof(file));
    }

    /// <summary>
    /// Acquires a connection lease (concurrency cap) then a pooled, authenticated session. The
    /// returned scope releases both on dispose. Credentials are resolved here and disposed
    /// immediately after the session is established — never retained (NEVER #1/#2).
    /// </summary>
    private async Task<SessionScope> OpenAsync(EndpointTarget target, TimeSpan connectTimeout, CancellationToken ct)
    {
        var plan = ConnectionPlanner.Plan(target);
        var key = ConnectionKey.For(plan);

        var lease = await _governor.AcquireAsync(target.TenantId, ct).ConfigureAwait(false);
        try
        {
            var pooled = await _pool.AcquireAsync(
                key,
                // The factory resolves each hop's secret at the moment of connect and disposes it
                // immediately — this connector never holds credential material (NEVER #1/#2).
                token => _sessionFactory.ConnectAsync(plan, _credentials.ResolveAsync, connectTimeout, token),
                ct).ConfigureAwait(false);

            return new SessionScope(lease, pooled);
        }
        catch
        {
            await lease.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static void RequirePositiveTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(timeout), timeout, "Every remote operation must be time-bounded (CLAUDE.md NEVER #5).");
    }

    private static string DoubleHopMessage(DoubleHopAssessment hop) =>
        $"Double-hop required and credential delegation is not enabled for this target: {hop.Reason} " +
        "Push the payload to the target and run it locally, or enable scoped delegation on the target.";

    /// <summary>Holds a concurrency lease + a pooled session; disposes both (session returns to pool).</summary>
    private sealed class SessionScope(IConnectionLease lease, SshConnectionPool.PooledSessionLease pooled) : IAsyncDisposable
    {
        public ISshSession Session => pooled.Session;

        public async ValueTask DisposeAsync()
        {
            pooled.Dispose();
            await lease.DisposeAsync().ConfigureAwait(false);
        }
    }
}
