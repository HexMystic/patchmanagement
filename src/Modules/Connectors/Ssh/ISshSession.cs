using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Ssh;

/// <summary>
/// A live, authenticated SSH session — the seam between <see cref="SshConnector"/>/the pool and the
/// concrete SSH.NET transport. Faking this makes the connector, pool and governor unit-testable
/// without a real SSH server; the real implementation (<c>SshNetSession</c>) is exercised by the
/// integration suite against the lab fleet.
/// </summary>
internal interface ISshSession : IDisposable
{
    bool IsConnected { get; }

    /// <summary>Run a command with an explicit timeout; a hung command is cancelled, never awaited forever.</summary>
    Task<CommandResult> RunAsync(string commandLine, TimeSpan timeout, CancellationToken ct);

    /// <summary>Upload <paramref name="content"/> to <paramref name="remotePath"/> via SFTP. Returns bytes written.</summary>
    Task<long> UploadAsync(Stream content, string remotePath, TimeSpan timeout, CancellationToken ct);

    /// <summary>Download <paramref name="remotePath"/> into <paramref name="destination"/> via SFTP. Returns bytes read.</summary>
    Task<long> DownloadAsync(string remotePath, Stream destination, TimeSpan timeout, CancellationToken ct);
}
