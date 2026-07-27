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

    /// <summary>
    /// Run a command with an explicit timeout; a hung command is cancelled, never awaited forever.
    ///
    /// <para><paramref name="stdin"/> carries bytes written to the command's standard input and
    /// closed — used for <c>sudo -S</c>, which reads the password from stdin. It exists precisely so
    /// an elevation secret never has to appear on the command line, where it would be visible in the
    /// target's process list to every local user and in any shell history.</para>
    ///
    /// <para>The caller owns and zeroes the buffer; the session must not retain it past the call.</para>
    /// </summary>
    Task<CommandResult> RunAsync(
        string commandLine, TimeSpan timeout, ReadOnlyMemory<byte> stdin, CancellationToken ct);

    /// <summary>Upload <paramref name="content"/> to <paramref name="remotePath"/> via SFTP. Returns bytes written.</summary>
    Task<long> UploadAsync(Stream content, string remotePath, TimeSpan timeout, CancellationToken ct);

    /// <summary>Download <paramref name="remotePath"/> into <paramref name="destination"/> via SFTP. Returns bytes read.</summary>
    Task<long> DownloadAsync(string remotePath, Stream destination, TimeSpan timeout, CancellationToken ct);
}
