using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// An <see cref="ISshSession"/> that records what it was asked to do and returns canned results.
/// Lets the connector's command construction — elevation, stdin, transfers — be asserted without a
/// real SSH server, which is the only way to test the <c>sudo -S</c> path at all: the dev lab grants
/// NOPASSWD sudo and locks the account password, so it can never demand one.
/// </summary>
internal sealed class RecordingSshSession : ISshSession
{
    private readonly Func<string, CommandResult>? _resultFor;

    public RecordingSshSession(Func<string, CommandResult>? resultFor = null) => _resultFor = resultFor;

    public bool IsConnected { get; private set; } = true;
    public bool Disposed { get; private set; }

    /// <summary>Command lines in call order, exactly as the connector built them.</summary>
    public List<string> CommandLines { get; } = [];

    /// <summary>
    /// A COPY of each stdin payload, taken at call time. A copy is essential: the connector zeroes
    /// its buffer when the call returns, so holding the original would show all zeros and the
    /// assertion would pass for the wrong reason.
    /// </summary>
    public List<byte[]> StdinPayloads { get; } = [];

    /// <summary>The caller's buffers themselves, to assert the connector zeroed them afterwards.</summary>
    public List<ReadOnlyMemory<byte>> StdinBuffersAsPassed { get; } = [];

    public List<string> Uploads { get; } = [];
    public List<string> Downloads { get; } = [];

    public Task<CommandResult> RunAsync(
        string commandLine, TimeSpan timeout, ReadOnlyMemory<byte> stdin, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        CommandLines.Add(commandLine);
        StdinPayloads.Add(stdin.ToArray());
        StdinBuffersAsPassed.Add(stdin);

        var result = _resultFor?.Invoke(commandLine)
                     ?? CommandResult.Ran(0, "ok", string.Empty, TimeSpan.FromMilliseconds(1));
        return Task.FromResult(result);
    }

    public Task<long> UploadAsync(Stream content, string remotePath, TimeSpan timeout, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Uploads.Add(remotePath);
        using var sink = new MemoryStream();
        content.CopyTo(sink);
        return Task.FromResult(sink.Length);
    }

    public Task<long> DownloadAsync(string remotePath, Stream destination, TimeSpan timeout, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Downloads.Add(remotePath);
        var payload = "downloaded"u8.ToArray();
        destination.Write(payload);
        return Task.FromResult((long)payload.Length);
    }

    public void Dispose()
    {
        Disposed = true;
        IsConnected = false;
    }
}
