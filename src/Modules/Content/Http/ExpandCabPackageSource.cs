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
/// <para><b>⚠ BROKEN — THIS CANNOT EXTRACT THE REAL CAB. Confirmed 2026-08-16 against the real
/// 658&#160;MB <c>lab/content/wsusscn2.cab</c>; do not assume it works.</b></para>
///
/// <para><b>Defect 1 — the destination must be a directory.</b> <c>wsusscn2.cab</c> is a
/// <i>multi-file</i> cab, and <c>expand.exe</c> refuses a file destination for one:
/// <c>"Destination directory required for a multi-file CAB."</c> (exit 2). <see cref="RunExpandAsync"/>
/// passes a file path, so the <b>first</b> call fails every time and this throws
/// <c>expand.exe failed extracting 'package.cab' (exit 2)</c>. The inner <c>package.cab</c> IS
/// single-file, so the second call's file destination is correct — only the outer call is wrong.</para>
///
/// <para><b>Defect 2 — one cab of 75.</b> The real cab holds <c>index.xml</c> plus
/// <c>package.cab</c> and <c>package2..75.cab</c>. <c>index.xml</c> is Microsoft's manifest
/// (<c>&lt;CAB NAME= RANGESTART= /&gt;</c>) and is never read. <c>package.xml</c> alone is the update
/// graph only: KB numbers, titles and the software/category flag all live in the shards.</para>
///
/// <para><b>Correction.</b> The previous TODO said the normalization was "fully tested independently
/// of this extractor". It is not tested at all — see
/// <see cref="PatchManagement.Content.Connectors.Wsusscn2Connector"/>.</para>
///
/// <para>Rewrite owner <b>D-504</b>. Weigh WiX DTF (<c>Microsoft.Deployment.Compression.Cab</c>) for
/// managed random access instead of expanding gigabytes to disk — and note that a managed reader
/// would also drop the Windows-only constraint below.</para>
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
