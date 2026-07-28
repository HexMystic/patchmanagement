using System.Diagnostics;
using System.Net;
using System.Security;
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

    private readonly Func<ResolvedCredential, HttpMessageHandler> _handlerFactory;

    /// <param name="handlerFactory">
    /// Builds the message handler for a credential. Defaults to <see cref="BuildAuthenticatedHandler"/>;
    /// tests substitute a scripted handler, which is what makes this class testable at all without a
    /// Windows host.
    ///
    /// <para>It takes the credential rather than being a plain <c>IHttpClientFactory</c> deliberately.
    /// A pooled, named client cannot carry per-target credentials, and the previous code proved why:
    /// when a factory was present it returned the pooled client and DISCARDED the NetworkCredential
    /// it had just built, so every WinRM call went out unauthenticated. Authentication is a property
    /// of the handler, so the credential has to reach the thing that builds it.</para>
    /// </param>
    public HttpWinRmClient(Func<ResolvedCredential, HttpMessageHandler>? handlerFactory = null) =>
        _handlerFactory = handlerFactory ?? BuildAuthenticatedHandler;

    /// <summary>
    /// The production handler. Always carries the credential — there is no branch that can drop it.
    ///
    /// <para><b>The password goes in as a <see cref="SecureString"/>, never a <see cref="string"/>.</b>
    /// This previously did <c>Encoding.UTF8.GetString(credential.Secret)</c> and called the result
    /// transient. It is not: a .NET string is immutable, so it cannot be zeroed and survives on the
    /// managed heap until some later GC — visible in a process dump for that whole window, and the GC
    /// may copy it while compacting, leaving further copies behind. Every other credential path in
    /// this codebase is built on zeroing in place (<c>CryptographicOperations.ZeroMemory</c> in
    /// <c>SshConnector</c>, <c>ResolvedCredential.Dispose</c>, <c>Array.Clear</c> after parsing a
    /// key), and there is a test asserting the sudo stdin buffer is all zeros afterwards. This one
    /// path silently opted out while its comment claimed the opposite.</para>
    ///
    /// <para><c>SecureString</c> is not a strong boundary on its own — the platform decrypts it to
    /// unmanaged memory at the point of use — but it is what <see cref="NetworkCredential"/> accepts
    /// for exactly this purpose, and its lifetime is bounded and zeroed rather than left to the
    /// collector. Bounded and wiped beats indefinite and immutable.</para>
    /// </summary>
    internal static HttpClientHandler BuildAuthenticatedHandler(ResolvedCredential credential) =>
        new()
        {
            Credentials = new NetworkCredential(
                credential.Username,
                ToSecureString(credential.Secret)),
            PreAuthenticate = true,
        };

    /// <summary>
    /// Copies UTF-8 secret bytes into a <see cref="SecureString"/> without ever materialising a
    /// managed <see cref="string"/>.
    ///
    /// <para>Decoded through a char buffer that is wiped in a <c>finally</c>, because
    /// <c>Encoding.UTF8.GetString</c> would reintroduce precisely the immortal copy this exists to
    /// avoid. The buffer is sized by <c>GetMaxCharCount</c> so a multi-byte password cannot overflow
    /// it — a password is arbitrary user text, not ASCII.</para>
    /// </summary>
    private static SecureString ToSecureString(ReadOnlySpan<byte> utf8Secret)
    {
        var chars = new char[Encoding.UTF8.GetMaxCharCount(utf8Secret.Length)];
        try
        {
            var written = Encoding.UTF8.GetChars(utf8Secret, chars);

            var secure = new SecureString();
            for (var i = 0; i < written; i++) secure.AppendChar(chars[i]);

            secure.MakeReadOnly();
            return secure;
        }
        finally
        {
            Array.Clear(chars);
        }
    }

    /// <summary>
    /// Proves the endpoint is reachable AND that the credential is accepted.
    ///
    /// <para>This used to send a WS-Man <c>Identify</c>, which many configurations answer
    /// <b>without authentication</b> — so a probe with an entirely wrong credential returned success
    /// and the endpoint was reported healthy. Creating and deleting a shell is the cheapest exchange
    /// that a server will not perform for an unauthenticated caller, so a rejected credential is now
    /// rejected here rather than at the first real operation.</para>
    /// </summary>
    public async Task ProbeAsync(EndpointTarget target, ResolvedCredential credential, TimeSpan timeout, CancellationToken ct)
    {
        var url = EndpointUrl(target);
        using var http = CreateClient(credential, timeout);

        var createReply = await PostAsync(http, url, WinRmMessageBuilder.CreateShell(url, timeout), timeout, ct)
            .ConfigureAwait(false);

        var shellId = SelectValue(createReply, W + "Selector", "ShellId") ?? SelectValue(createReply, Rsp + "ShellId", null);
        if (shellId is null)
        {
            throw new ConnectorConnectException(
                ConnectorOutcome.ProtocolError, "WinRM did not return a ShellId for the connectivity probe.");
        }

        // Best-effort cleanup: the probe has already proven what it needed to.
        try
        {
            await PostAsync(http, url, WinRmMessageBuilder.DeleteShell(url, shellId, timeout), timeout, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch
        {
            // A shell we could not delete does not make the endpoint unreachable or the credential bad.
        }
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

            // Bounded by the operation's own deadline, not only by the caller's token.
            //
            // This loop previously exited on ct alone, so a server that accepted the command and then
            // never reported CommandState/Done kept it polling until the caller happened to cancel —
            // and a caller that passed CancellationToken.None would poll forever, holding a connection
            // slot against the process-wide budget. NEVER #5 says no unbounded remote wait ever, and
            // "the caller can always cancel" is not a bound the connector provides.
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (timeout > TimeSpan.Zero) deadline.CancelAfter(timeout);

            while (exitCode is null)
            {
                if (deadline.IsCancellationRequested && !ct.IsCancellationRequested)
                {
                    throw new ConnectorConnectException(
                        ConnectorOutcome.Timeout,
                        "WinRM command did not report completion within its time budget.");
                }

                ct.ThrowIfCancellationRequested();

                // The CALLER's token, not the deadline's. PostAsync distinguishes caller cancellation
                // (rethrow untouched) from its own timeout (map to Outcome.Timeout) by asking whether
                // the token it was given is cancelled — so handing it the deadline token would make
                // every expiry look like the caller pulling out, and the honest Timeout would be lost.
                // The overall bound is enforced by the check at the top of this loop instead.
                var receive = await PostAsync(
                    http, url, WinRmMessageBuilder.Receive(url, shellId, commandId, timeout), timeout, ct)
                    .ConfigureAwait(false);

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
        // The remote path is escaped, not interpolated: an apostrophe in it would otherwise close the
        // literal and turn the remainder into executable PowerShell in an administrative session.
        var ps = $"$d=[Convert]::FromBase64String({WinRmMessageBuilder.SingleQuoted(b64)}); "
                 + $"[IO.File]::WriteAllBytes({WinRmMessageBuilder.SingleQuoted(file.RemotePath)},$d)";
        var result = await ExecuteAsync(target, credential, "powershell -NonInteractive -EncodedCommand " + EncodePowerShell(ps), file.Timeout, ct).ConfigureAwait(false);
        if (!result.Succeeded || result.ExitCode != 0)
        {
            // A BOUNDED reason code, never the remote text. This message becomes FileResult.Detail,
            // which a caller will log — and remote stderr is arbitrary content from the endpoint that
            // may quote back the command line, an environment variable, or whatever the failing tool
            // decided to print. The connector cannot know, so it does not forward it into a
            // diagnostic. The output itself remains available on CommandResult for a caller that
            // genuinely wants it (ADR 0012's hand-off to Phase 3).
            throw new ConnectorConnectException(
                ConnectorOutcome.ProtocolError, ConnectorReason.WinRmUploadFailed);
        }

        return content.LongLength;
    }

    public async Task<long> DownloadAsync(
        EndpointTarget target, ResolvedCredential credential, FileTransfer file, Stream destination, CancellationToken ct)
    {
        var ps = $"[Convert]::ToBase64String([IO.File]::ReadAllBytes({WinRmMessageBuilder.SingleQuoted(file.RemotePath)}))";
        var result = await ExecuteAsync(target, credential, "powershell -NonInteractive -EncodedCommand " + EncodePowerShell(ps), file.Timeout, ct).ConfigureAwait(false);
        if (!result.Succeeded || result.ExitCode != 0)
        {
            throw new ConnectorConnectException(
                ConnectorOutcome.ProtocolError, ConnectorReason.WinRmDownloadFailed);
        }

        var bytes = Convert.FromBase64String(result.StandardOutput.Trim());
        await destination.WriteAsync(bytes, ct).ConfigureAwait(false);
        return bytes.LongLength;
    }

    private HttpClient CreateClient(ResolvedCredential credential, TimeSpan timeout)
    {
        if (credential.Kind != CredentialKind.WindowsPassword)
            throw new ConnectorConnectException(ConnectorOutcome.AuthFailed, "WinRM connector requires a Windows password credential.");

        var client = new HttpClient(_handlerFactory(credential), disposeHandler: true)
        {
            Timeout = timeout > TimeSpan.Zero ? timeout + TimeSpan.FromSeconds(5) : Timeout.InfiniteTimeSpan,
        };

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
