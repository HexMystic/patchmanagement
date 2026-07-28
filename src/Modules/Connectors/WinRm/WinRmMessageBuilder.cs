using System.Globalization;
using System.Security;
using System.Xml.Linq;

namespace PatchManagement.Connectors.WinRm;

/// <summary>
/// Builds WS-Management (MS-WSMV) SOAP envelopes for the PowerShell/cmd shell lifecycle:
/// Identify, Create shell, run Command, Receive output, Signal (terminate), Delete shell. These are
/// the protocol details that can be verified without a live Windows host, so this is the WinRM
/// connector's unit-tested core. The HTTP transport merely POSTs these envelopes and parses replies.
///
/// Every envelope carries an explicit <c>wsman:OperationTimeout</c> derived from the caller's budget,
/// so the server itself bounds the operation — there is no unbounded remote wait (NEVER #5).
/// </summary>
public static class WinRmMessageBuilder
{
    public const string ShellResourceUri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

    private static readonly XNamespace S = "http://www.w3.org/2003/05/soap-envelope";
    private static readonly XNamespace A = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    private static readonly XNamespace W = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
    private static readonly XNamespace Rsp = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
    private static readonly XNamespace WsmId = "http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd";
    private static readonly XNamespace Transfer = "http://schemas.xmlsoap.org/ws/2004/09/transfer";

    private const string CreateAction = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
    private const string DeleteAction = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";
    private const string CommandAction = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
    private const string ReceiveAction = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
    private const string SignalAction = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
    private const string TerminateSignal = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/Terminate";

    public static string Identify() =>
        new XDocument(new XElement(S + "Envelope",
            NamespaceAttr("s", S), NamespaceAttr("wsmid", WsmId),
            new XElement(S + "Header"),
            new XElement(S + "Body", new XElement(WsmId + "Identify")))).ToString();

    public static string CreateShell(string endpointUrl, TimeSpan operationTimeout) =>
        Envelope(CreateAction, endpointUrl, operationTimeout, selectorShellId: null,
            body: new XElement(Rsp + "Shell",
                new XElement(Rsp + "InputStreams", "stdin"),
                new XElement(Rsp + "OutputStreams", "stdout stderr")));

    public static string Command(string endpointUrl, string shellId, string commandLine, TimeSpan operationTimeout) =>
        Envelope(CommandAction, endpointUrl, operationTimeout, selectorShellId: shellId,
            body: new XElement(Rsp + "CommandLine",
                new XElement(Rsp + "Command", XmlSafe(commandLine))));

    public static string Receive(string endpointUrl, string shellId, string commandId, TimeSpan operationTimeout) =>
        Envelope(ReceiveAction, endpointUrl, operationTimeout, selectorShellId: shellId,
            body: new XElement(Rsp + "Receive",
                new XElement(Rsp + "DesiredStream", new XAttribute("CommandId", commandId), "stdout stderr")));

    public static string Terminate(string endpointUrl, string shellId, string commandId, TimeSpan operationTimeout) =>
        Envelope(SignalAction, endpointUrl, operationTimeout, selectorShellId: shellId,
            body: new XElement(Rsp + "Signal", new XAttribute("CommandId", commandId),
                new XElement(Rsp + "Code", TerminateSignal)));

    public static string DeleteShell(string endpointUrl, string shellId, TimeSpan operationTimeout) =>
        Envelope(DeleteAction, endpointUrl, operationTimeout, selectorShellId: shellId, body: null);

    /// <summary>WS-Man ISO-8601 duration, e.g. a 60s budget → <c>PT60.000S</c>.</summary>
    public static string ToOperationTimeout(TimeSpan timeout) =>
        FormattableString.Invariant($"PT{timeout.TotalSeconds:0.000}S");

    private static string Envelope(
        string action, string endpointUrl, TimeSpan operationTimeout, string? selectorShellId, XElement? body)
    {
        var header = new XElement(S + "Header",
            new XElement(A + "To", endpointUrl),
            new XElement(W + "ResourceURI", new XAttribute(S + "mustUnderstand", "true"), ShellResourceUri),
            new XElement(A + "Action", new XAttribute(S + "mustUnderstand", "true"), action),
            new XElement(A + "MessageID", "uuid:" + Guid.NewGuid().ToString("D")),
            new XElement(W + "OperationTimeout", ToOperationTimeout(operationTimeout)),
            new XElement(A + "ReplyTo",
                new XElement(A + "Address", new XAttribute(S + "mustUnderstand", "true"),
                    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous")));

        if (selectorShellId is not null)
        {
            header.Add(new XElement(W + "SelectorSet",
                new XElement(W + "Selector", new XAttribute("Name", "ShellId"), selectorShellId)));
        }

        var envelope = new XElement(S + "Envelope",
            NamespaceAttr("s", S), NamespaceAttr("a", A), NamespaceAttr("w", W),
            NamespaceAttr("rsp", Rsp), NamespaceAttr("t", Transfer),
            header,
            new XElement(S + "Body", body is null ? null : body));

        return new XDocument(envelope).ToString();
    }

    private static XAttribute NamespaceAttr(string prefix, XNamespace ns) =>
        new(XNamespace.Xmlns + prefix, ns.NamespaceName);

    // XDocument escapes text on serialization; this guards against embedded control chars only.
    private static string XmlSafe(string value) => new(value.Where(c => c >= 0x20 || c is '\t' or '\n' or '\r').ToArray());

    /// <summary>Renders a password into a transient char span for the HTTP handler; caller clears it.</summary>
    /// <summary>
    /// Quotes a value for use inside a PowerShell <b>single-quoted</b> literal.
    ///
    /// <para>Remote paths were interpolated raw into <c>'...'</c>, so a path containing an apostrophe
    /// closed the literal and everything after it became executable PowerShell — running with
    /// whatever privileges the WinRM session holds, which for a patching product is administrative.
    /// A path is attacker-influenced whenever it comes from inventory, a manifest or an operator
    /// pasting a value, so this is a live injection vector rather than a robustness nicety.</para>
    ///
    /// <para>Inside a single-quoted PowerShell literal the ONLY metacharacter is the apostrophe, and
    /// it is escaped by doubling. Nothing else — <c>$</c>, backtick, <c>;</c>, newline — is special
    /// there, which is exactly why single quotes are the right container and why the escaping is
    /// this small.</para>
    /// </summary>
    internal static string SingleQuoted(string? value) =>
        "'" + (value ?? string.Empty).Replace("'", "''", StringComparison.Ordinal) + "'";
}
