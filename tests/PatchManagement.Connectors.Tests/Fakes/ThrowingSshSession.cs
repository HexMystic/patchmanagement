using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// A session whose every operation throws a caller-chosen exception — the stand-in for a transport
/// that fails in a way the connector does not model.
///
/// <para>It exists because that case turned out not to be hypothetical: SSH.NET threw
/// <c>InvalidOperationException</c> out of the stdin path and it escaped the connector raw. Every
/// other fake here fails in a way the connector already understands, which is why none of them could
/// have caught it.</para>
/// </summary>
internal sealed class ThrowingSshSession(Exception thrown) : ISshSession
{
    public bool IsConnected => true;

    public Task<CommandResult> RunAsync(
        string commandLine, TimeSpan timeout, ReadOnlyMemory<byte> stdin, CancellationToken ct) =>
        throw thrown;

    public Task<long> UploadAsync(Stream content, string remotePath, TimeSpan timeout, CancellationToken ct) =>
        throw thrown;

    public Task<long> DownloadAsync(string remotePath, Stream destination, TimeSpan timeout, CancellationToken ct) =>
        throw thrown;

    public void Dispose() { }
}
