using System.Diagnostics;
using PatchManagement.Content.Abstractions;

namespace PatchManagement.Content.Http;

/// <summary>
/// Production <see cref="IWsusPackageSource"/> — extracts <c>package.xml</c> from
/// <c>wsusscn2.cab</c> by shelling out to Windows <c>expand.exe</c> (there is no built-in
/// cross-platform CAB reader in .NET, and pulling a third-party native CAB library was out of scope
/// for this slice). The cab nests: <c>wsusscn2.cab → package.cab → package.xml</c>, so two expand
/// passes are needed. Time-bounded via the process wait + the caller's token (NEVER #5).
///
/// TODO(phase-5-followup): this path is IMPLEMENTED but NOT yet exercised against the real ~627&#160;MB
/// <c>lab/content/wsusscn2.cab</c> in this session — the ~1&#160;GB uncompressed package.xml and
/// Windows-only <c>expand.exe</c> dependency make it an integration concern to validate on a Windows
/// runner. The connector's XML normalization (<see cref="PatchManagement.Content.Connectors.Wsusscn2Connector"/>)
/// is fully tested independently of this extractor. Alternatives to weigh then: WiX DTF
/// (<c>Microsoft.Deployment.Compression.Cab</c>) for a managed, cross-platform reader.
/// </summary>
public sealed class ExpandCabPackageSource : IWsusPackageSource
{
    private static readonly TimeSpan ExtractTimeout = TimeSpan.FromMinutes(10);

    public async Task<Stream> OpenPackageXmlAsync(string cabPath, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "ExpandCabPackageSource uses Windows expand.exe. On other platforms supply an "
                + "alternative IWsusPackageSource (e.g. a managed CAB reader).");
        if (!File.Exists(cabPath))
            throw new FileNotFoundException("wsusscn2.cab not found.", cabPath);

        var work = Directory.CreateTempSubdirectory("wsusscn2_");
        try
        {
            var packageCab = Path.Combine(work.FullName, "package.cab");
            await RunExpandAsync(cabPath, "package.cab", packageCab, ct);

            var packageXml = Path.Combine(work.FullName, "package.xml");
            await RunExpandAsync(packageCab, "package.xml", packageXml, ct);

            // Copy into memory so the temp dir can be cleaned up before the caller reads.
            var bytes = await File.ReadAllBytesAsync(packageXml, ct);
            return new MemoryStream(bytes, writable: false);
        }
        finally
        {
            try { work.Delete(recursive: true); } catch (IOException) { /* best-effort cleanup */ }
        }
    }

    private static async Task RunExpandAsync(string source, string member, string destination, CancellationToken ct)
    {
        var psi = new ProcessStartInfo("expand.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(source);
        psi.ArgumentList.Add($"-F:{member}");
        psi.ArgumentList.Add(destination);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start expand.exe.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ExtractTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw;
        }

        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"expand.exe failed extracting '{member}' (exit {process.ExitCode}).");
    }
}
