using System.Net;
using System.Text;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Connectors.WinRm;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Tests.WinRm;

/// <summary>
/// Transport-seam proofs for the WinRM client.
///
/// <para><b>These are not end-to-end.</b> Every one runs against a scripted HTTP handler; no Windows
/// host exists in this environment and the guardrail forbids WinRM from a dev session (NEVER #4). A
/// green run here says the client sends what it should and reacts correctly to what it is told. It
/// does NOT say a real WinRM server accepts these exchanges. WinRM remains written-and-unverified,
/// and real-host verification stays deferred as D-303 with Phase 8 as its owner.</para>
/// </summary>
public sealed class HttpWinRmClientTests
{
    private static readonly Guid Tenant = Guid.Parse("c0ffee00-0000-0000-0000-000000000001");

    private static ResolvedCredential Credential() =>
        new(CredentialKind.WindowsPassword, "s3cr3t"u8.ToArray(), "Administrator");

    private static EndpointTarget Target() => new()
    {
        TenantId = Tenant,
        Host = "winhost.example.net",
        Port = 5986,
        Protocol = EndpointProtocol.WinRm,
        Credential = new CredentialRef(Guid.NewGuid()),
    };

    private const string ShellReply =
        """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><w:Selector Name="ShellId">SH1</w:Selector></s:Body></s:Envelope>""";

    // ---------------------------------------------------------------- defect (a): dropped credential

    [Fact]
    public void The_production_handler_always_carries_the_credential()
    {
        using var credential = Credential();

        var handler = HttpWinRmClient.BuildAuthenticatedHandler(credential);

        // There is no longer a branch that can return a handler without credentials. The previous
        // code had one — when an IHttpClientFactory was registered it returned the pooled client and
        // silently discarded the NetworkCredential it had just constructed, so every call went out
        // unauthenticated and came back 401, i.e. AuthFailed for a perfectly good credential.
        var network = Assert.IsType<NetworkCredential>(handler.Credentials);
        Assert.Equal("Administrator", network.UserName);
        Assert.Equal("s3cr3t", network.Password);
        Assert.True(handler.PreAuthenticate);
    }

    // ---------------------------------------------------------------- defect (d): unauthenticated probe

    [Fact]
    public async Task A_probe_fails_when_the_credential_is_rejected_even_if_identify_would_answer()
    {
        // The exploit shape: a server that answers Identify anonymously (very common) but rejects
        // the credential on any real operation. The old probe sent only Identify and reported the
        // endpoint healthy, so a wrong or expired credential was discovered later — during a
        // deployment wave rather than during a connectivity check.
        var handler = new ScriptedHttpHandler()
            .When("Identify", HttpStatusCode.OK, "<identify-ok/>")
            .When(body => body.Contains("shell/Create", StringComparison.OrdinalIgnoreCase)
                          || body.Contains(":Shell", StringComparison.OrdinalIgnoreCase),
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.Unauthorized, "<denied/>"));

        var client = new HttpWinRmClient(_ => handler);
        using var credential = Credential();

        var ex = await Assert.ThrowsAsync<ConnectorConnectException>(() =>
            client.ProbeAsync(Target(), credential, TimeSpan.FromSeconds(5), CancellationToken.None));

        Assert.Equal(ConnectorOutcome.AuthFailed, ex.Outcome);
    }

    [Fact]
    public async Task A_probe_performs_an_authenticated_exchange_rather_than_only_identify()
    {
        var handler = new ScriptedHttpHandler()
            .When(body => true, _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, ShellReply));

        var client = new HttpWinRmClient(_ => handler);
        using var credential = Credential();

        await client.ProbeAsync(Target(), credential, TimeSpan.FromSeconds(5), CancellationToken.None);

        // Asserting on what went ON THE WIRE, because "it returned success" is exactly what the
        // broken version did too.
        Assert.NotEmpty(handler.Requests);
        Assert.Contains(handler.Requests, r => r.Contains("Shell", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            handler.Requests,
            r => r.Contains("Identify", StringComparison.OrdinalIgnoreCase) && handler.Requests.Count == 1);
    }

    // ---------------------------------------------------------------- defect (b): unbounded receive loop

    // The only test here with a hard timeout, and it earns it: the defect under test is an UNBOUNDED
    // loop, so if the bound regresses this does not fail — it hangs the suite forever, which reads as
    // broken infrastructure rather than a broken guarantee.
    [Fact(Timeout = 15000)]
    public async Task A_command_that_never_reports_completion_is_bounded_by_its_own_budget()
    {
        // A server that accepts the command and then never says Done. The loop previously exited on
        // the caller's token alone, so with CancellationToken.None it polled forever, holding a
        // connection slot against the process-wide budget (NEVER #5).
        var handler = new ScriptedHttpHandler()
            .When(body => body.Contains("shell/Command", StringComparison.OrdinalIgnoreCase)
                          || body.Contains("CommandLine", StringComparison.OrdinalIgnoreCase),
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK,
                      """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:CommandId>C1</rsp:CommandId></s:Body></s:Envelope>"""))
            .When(body => body.Contains("Receive", StringComparison.OrdinalIgnoreCase),
                  // Always "still running": no CommandState/Done, ever.
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK,
                      """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><still-running/></s:Body></s:Envelope>"""))
            .When(body => true, _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, ShellReply));

        var client = new HttpWinRmClient(_ => handler);
        using var credential = Credential();
        var budget = TimeSpan.FromMilliseconds(500);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ex = await Assert.ThrowsAsync<ConnectorConnectException>(() => client.ExecuteAsync(
            Target(), credential, "whoami", budget, CancellationToken.None));
        sw.Stop();

        Assert.Equal(ConnectorOutcome.Timeout, ex.Outcome);

        // ELAPSED, not just the outcome — and this assertion is the whole test.
        //
        // Without it the test passes against an unbounded loop: the loop spins on an instant fake
        // transport until incidental slowness eventually pushes one request past its own per-POST
        // timeout, which surfaces as Outcome.Timeout after ~95 seconds. That is the right outcome for
        // entirely the wrong reason, and it is exactly what the first version of this test did.
        Assert.True(
            sw.Elapsed < TimeSpan.FromSeconds(10),
            $"the command took {sw.Elapsed.TotalSeconds:0.#}s against a {budget.TotalSeconds:0.#}s "
            + "budget, so the receive loop is not bounded by the budget — it merely stopped eventually.");
    }

    // ---------------------------------------------------------------- defect (c): PowerShell injection

    [Theory]
    [InlineData(@"C:\temp\it's.msu")]
    [InlineData(@"C:\x'; Remove-Item -Recurse -Force C:\ #")]
    [InlineData(@"C:\x'; Invoke-Expression $env:evil; '")]
    [InlineData("C:\\x';\r\nStop-Computer;'")]
    public async Task A_malicious_remote_path_cannot_break_out_of_the_powershell_literal(string remotePath)
    {
        var handler = ScriptedShellHandler();
        var client = new HttpWinRmClient(_ => handler);
        using var credential = Credential();

        await client.UploadAsync(
            Target(), credential,
            new FileTransfer { RemotePath = remotePath, Content = "payload"u8.ToArray() },
            CancellationToken.None);

        var script = DecodeCommand(handler);

        // The exploit is blocked when the path survives ONLY as a literal: every apostrophe it
        // contains must be doubled, which is the single escape single-quoted PowerShell recognises.
        // Asserting merely that a well-formed path still works would not distinguish this from the
        // broken version, which also handled well-formed paths.
        Assert.Contains(remotePath.Replace("'", "''", StringComparison.Ordinal), script, StringComparison.Ordinal);

        // ...and the injected text never appears in a position where PowerShell would execute it.
        Assert.DoesNotContain("Remove-Item", UnquotedPortionOf(script), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Invoke-Expression", UnquotedPortionOf(script), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Stop-Computer", UnquotedPortionOf(script), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_escaper_leaves_an_ordinary_path_readable()
    {
        // Control: escaping must not mangle the normal case, or people will route around it.
        Assert.Equal(@"'C:\temp\patch.msu'", WinRmMessageBuilder.SingleQuoted(@"C:\temp\patch.msu"));
    }

    [Fact]
    public void The_escaper_doubles_every_apostrophe()
    {
        Assert.Equal("'it''s'", WinRmMessageBuilder.SingleQuoted("it's"));
        Assert.Equal("'a''''b'", WinRmMessageBuilder.SingleQuoted("a''b"));
    }

    // ---------------------------------------------------------------- helpers

    private static ScriptedHttpHandler ScriptedShellHandler() =>
        new ScriptedHttpHandler()
            .When(body => body.Contains("CommandLine", StringComparison.OrdinalIgnoreCase),
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK,
                      """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:CommandId>C1</rsp:CommandId></s:Body></s:Envelope>"""))
            .When(body => body.Contains("Receive", StringComparison.OrdinalIgnoreCase),
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK,
                      """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></s:Body></s:Envelope>"""))
            .When(body => true, _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, ShellReply));

    /// <summary>The PowerShell the client actually generated, recovered from the -EncodedCommand.</summary>
    private static string DecodeCommand(ScriptedHttpHandler handler)
    {
        var commandRequest = handler.Requests.First(r => r.Contains("CommandLine", StringComparison.OrdinalIgnoreCase));

        var match = System.Text.RegularExpressions.Regex.Match(commandRequest, @"EncodedCommand\s+([A-Za-z0-9+/=]+)");
        Assert.True(match.Success, "no -EncodedCommand payload was found in the command request");

        return Encoding.Unicode.GetString(Convert.FromBase64String(match.Groups[1].Value));
    }

    /// <summary>
    /// The script with every single-quoted literal removed, i.e. the part PowerShell would actually
    /// execute. Injected text appearing here is a live breakout; inside a literal it is inert data.
    /// </summary>
    private static string UnquotedPortionOf(string script) =>
        System.Text.RegularExpressions.Regex.Replace(script, "'(?:[^']|'')*'", "<literal>");
}
