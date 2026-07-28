using System.Net;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// Ready-made <see cref="ScriptedHttpHandler"/> scripts for the WS-Man shell lifecycle, so tests that
/// care about something else (never-log sweeps, timeouts) do not each re-declare four SOAP envelopes.
///
/// <para>Still a transport-seam double, never a Windows host: these say what the client is TOLD, not
/// how a real WinRM server behaves. WinRM remains written-and-unverified (D-303, Phase 8).</para>
/// </summary>
internal static class WinRmScript
{
    private const string ShellReply =
        """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><w:Selector Name="ShellId">SH1</w:Selector></s:Body></s:Envelope>""";

    private const string CommandReply =
        """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:CommandId>C1</rsp:CommandId></s:Body></s:Envelope>""";

    /// <summary>A command that completes immediately with exit 0 and no output.</summary>
    private const string DoneReply =
        """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></s:Body></s:Envelope>""";

    /// <summary>The full happy path: create shell, run command, receive Done, terminate, delete.</summary>
    public static ScriptedHttpHandler Succeeding() =>
        new ScriptedHttpHandler()
            .When(body => body.Contains("CommandLine", StringComparison.OrdinalIgnoreCase),
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, CommandReply))
            .When(body => body.Contains("Receive", StringComparison.OrdinalIgnoreCase),
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, DoneReply))
            .When(_ => true, _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, ShellReply));

    /// <summary>
    /// A server that rejects the credential on any real operation. 401 is what drives the connector's
    /// only logging branch, which is where a careless diagnostic would surface a secret.
    /// </summary>
    public static ScriptedHttpHandler RejectingCredentials() =>
        new ScriptedHttpHandler()
            .When(_ => true, _ => ScriptedHttpHandler.Soap(HttpStatusCode.Unauthorized, "<denied/>"));

    /// <summary>
    /// A base64 payload echoed back on stdout, for download-shaped exchanges.
    /// </summary>
    public static ScriptedHttpHandler ReturningStdout(string base64Payload)
    {
        var receive =
            $"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:Stream Name="stdout">{Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(base64Payload))}</rsp:Stream><rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></s:Body></s:Envelope>""";

        return new ScriptedHttpHandler()
            .When(body => body.Contains("CommandLine", StringComparison.OrdinalIgnoreCase),
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, CommandReply))
            .When(body => body.Contains("Receive", StringComparison.OrdinalIgnoreCase),
                  _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, receive))
            .When(_ => true, _ => ScriptedHttpHandler.Soap(HttpStatusCode.OK, ShellReply));
    }
}
