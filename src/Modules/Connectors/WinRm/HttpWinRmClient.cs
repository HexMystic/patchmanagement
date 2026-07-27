using System.Diagnostics;
using System.Net;
using System.Text;
using System.Xml.Linq;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.WinRm;

/// <summary>
/// Real WS-Management/HTTPS transport for WinRM using <see cref="HttpClient"/> with Negotiate/NTLM
/// auth. This is a genuine implementation but is <b>integration-tested later</b> against remote
/// Windows cloud VMs — the dev lab has no Windows host and the guardrail forbids WinRM from a dev
/// session (CLAUDE.md NEVER #4). Its correctness-critical protocol logic (the SOAP envelopes) lives
/// in <see cref="WinRmMessageBuilder"/> and is unit-tested here and now.
///
/// Failures are surfaced as <see cref="ConnectorConnectException"/> with honest outcomes; secret
/// material is used transiently and never logged (NEVER #1/#2).
/// </summary>
internal sealed class HttpWinRmClient : IWinRmClient
{
    private static readonly XNamespace W = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
    private static readonly XNamespace Rsp = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";

    private readonly IHttpClientFactory? _httpClientFactory;

    public HttpWinRmClient(IHttpClientFactory? httpClientFactory = null) => _httpClientFactory = httpClientFactory;

    public async Task ProbeAsync(EndpointTarget target, ResolvedCredential credential, TimeSpan timeout, CancellationToken ct)
    {
        using var http = CreateClient(credential, timeout);
        await PostAsync(http, EndpointUrl(target), WinRmMessageBuilder.Identify(), timeout, ct).ConfigureAwait(false);
    }

    public async Task<CommandResult> ExecuteAsync(
        EndpointTarget target, ResolvedCredential credential, string command, TimeSpan timeout, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var url = EndpointUrl(target);
        using var http = CreateClient(credential, timeout);

        var createReply = await PostAsync(http, url, WinRmMessageBuilder.CreateShell(url, timeout), timeout, ct).ConfigureAwait(false);
        var shellId = SelectValue(createReply, W + "Selector", "ShellId") ?? SelectValue(createReply, Rsp + "ShellId", null)
            ?? throw new ConnectorConnectException(ConnectorOutcome.ProtocolError, "WinRM did not return a ShellId.");

        try
        {
            var commandReply = await PostAsync(http, url, WinRmMessageBuilder.Command(url, shellId, command, timeout), timeout, ct).ConfigureAwait(false);
            var commandId = SelectValue(commandReply, Rsp + "CommandId", null)
                ?? throw new ConnectorConnectException(ConnectorOutcome.ProtocolError, "WinRM did not return a CommandId.");

            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            int? exitCode = null;

            while (exitCode is null)
            {
                ct.ThrowIfCancellationRequested();
                var receive = await PostAsync(http, url, WinRmMessageBuilder.Receive(url, shellId, commandId, timeout), timeout, ct).ConfigureAwait(false);
                AppendStreams(receive, stdout, stderr);
                exitCode = ReadExitCodeIfDone(receive);
            }

            await PostAsync(http, url, WinRmMessageBuilder.Terminate(url, shellId, commandId, timeout), timeout, ct).ConfigureAwait(false);
            return CommandResult.Ran(exitCode.Value, stdout.ToString(), stderr.ToString(), sw.Elapsed);
        }
        finally
        {
            try { await PostAsync(http, url, WinRmMessageBuilder.DeleteShell(url, shellId, timeout), timeout, CancellationToken.None).ConfigureAwait(false); }
            catch { /* best-effort cleanup — never mask the real result */ }
        }
    }

    public async Task<long> UploadAsync(EndpointTarget target, ResolvedCredential credential, FileTransfer file, CancellationToken ct)
    {
        var content = file.Content?.ToArray() ?? await File.ReadAllBytesAsync(file.LocalPath!, ct).ConfigureAwait(false);
        var b64 = Convert.ToBase64String(content);
        // Push then run locally — this is exactly how a double-hop is avoided (HARD-PROBLEMS #9).
        var ps = $"$d=[Convert]::FromBase64String('{b64}'); [IO.File]::WriteAllBytes('{file.RemotePath}',$d)";
        var result = await ExecuteAsync(target, credential, "powershell -NonInteractive -EncodedCommand " + EncodePowerShell(ps), file.Timeout, ct).ConfigureAwait(false);
        if (!result.Succeeded || result.ExitCode != 0)
            throw new ConnectorConnectException(ConnectorOutcome.ProtocolError, "WinRM upload failed: " + (result.Detail ?? result.StandardError));
        return content.LongLength;
    }

    public async Task<long> DownloadAsync(
        EndpointTarget target, ResolvedCredential credential, FileTransfer file, Stream destination, CancellationToken ct)
    {
        var ps = $"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{file.RemotePath}'))";
        var result = await ExecuteAsync(target, credential, "powershell -NonInteractive -EncodedCommand " + EncodePowerShell(ps), file.Timeout, ct).ConfigureAwait(false);
        if (!result.Succeeded || result.ExitCode != 0)
            throw new ConnectorConnectException(ConnectorOutcome.ProtocolError, "WinRM download failed: " + (result.Detail ?? result.StandardError));
        var bytes = Convert.FromBase64String(result.StandardOutput.Trim());
        await destination.WriteAsync(bytes, ct).ConfigureAwait(false);
        return bytes.LongLength;
    }

    private HttpClient CreateClient(ResolvedCredential credential, TimeSpan timeout)
    {
        if (credential.Kind != CredentialKind.WindowsPassword)
            throw new ConnectorConnectException(ConnectorOutcome.AuthFailed, "WinRM connector requires a Windows password credential.");

        var networkCredential = new NetworkCredential(
            credential.Username,
            Encoding.UTF8.GetString(credential.Secret)); // transient; NetworkCredential requires a string

        HttpClient client;
        if (_httpClientFactory is not null)
        {
            client = _httpClientFactory.CreateClient("winrm");
        }
        else
        {
            var handler = new HttpClientHandler
            {
                Credentials = networkCredential,
                PreAuthenticate = true,
            };
            client = new HttpClient(handler, disposeHandler: true);
        }

        client.Timeout = timeout > TimeSpan.Zero ? timeout + TimeSpan.FromSeconds(5) : Timeout.InfiniteTimeSpan;
        return client;
    }

    private static async Task<XDocument> PostAsync(HttpClient http, string url, string soap, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeout > TimeSpan.Zero) cts.CancelAfter(timeout);

        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(soap, Encoding.UTF8, "application/soap+xml"),
        };

        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cts.Token).ConfigureAwait(false);
            var payload = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                throw new ConnectorConnectException(ConnectorOutcome.AuthFailed, "WinRM authentication was rejected.");
            if (!response.IsSuccessStatusCode)
                throw new ConnectorConnectException(ConnectorOutcome.ProtocolError, $"WinRM returned HTTP {(int)response.StatusCode}.");

            return string.IsNullOrWhiteSpace(payload) ? new XDocument() : XDocument.Parse(payload);
        }
        catch (ConnectorConnectException)
        {
            throw;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw new ConnectorConnectException(ConnectorOutcome.Timeout, "WinRM request timed out.");
        }
        catch (HttpRequestException ex)
        {
            throw new ConnectorConnectException(ConnectorOutcome.Unreachable, "WinRM endpoint could not be reached.", ex);
        }
    }

    private static string EndpointUrl(EndpointTarget target)
    {
        var port = target.EffectivePort;
        return $"https://{target.Host}:{port}/wsman";
    }

    private static string? SelectValue(XDocument doc, XName elementName, string? selectorNameAttr)
    {
        foreach (var el in doc.Descendants(elementName))
        {
            if (selectorNameAttr is null)
                return el.Value;
            if ((string?)el.Attribute("Name") == selectorNameAttr)
                return el.Value;
        }
        return null;
    }

    private static void AppendStreams(XDocument doc, StringBuilder stdout, StringBuilder stderr)
    {
        foreach (var stream in doc.Descendants(Rsp + "Stream"))
        {
            if (string.IsNullOrEmpty(stream.Value)) continue;
            var text = Encoding.UTF8.GetString(Convert.FromBase64String(stream.Value));
            var target = (string?)stream.Attribute("Name") == "stderr" ? stderr : stdout;
            target.Append(text);
        }
    }

    private static int? ReadExitCodeIfDone(XDocument doc)
    {
        var state = doc.Descendants(Rsp + "CommandState").FirstOrDefault();
        if (state is null) return null;
        var isDone = ((string?)state.Attribute("State"))?.EndsWith("/Done", StringComparison.Ordinal) == true;
        if (!isDone) return null;
        var exit = state.Element(Rsp + "ExitCode")?.Value;
        return int.TryParse(exit, out var code) ? code : 0;
    }

    private static string EncodePowerShell(string script) =>
        Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
}
