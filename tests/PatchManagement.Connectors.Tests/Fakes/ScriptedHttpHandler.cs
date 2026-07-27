using System.Net;
using System.Text;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// A scripted WS-Man transport: answers each POST from a rule matched on the SOAP body.
///
/// <para>This is what makes <c>HttpWinRmClient</c> itself testable. Until now only the connector
/// ABOVE it could be faked, so the client's own protocol handling — the receive loop, the probe
/// exchange, the generated PowerShell — had no coverage at all and its defects were invisible.</para>
///
/// <para>It is a transport-seam double, not a Windows host. Everything proven with it is a statement
/// about what this client SENDS and how it reacts to what it is told, never a statement that a real
/// WinRM server behaves this way.</para>
/// </summary>
internal sealed class ScriptedHttpHandler : HttpMessageHandler
{
    private readonly List<(Func<string, bool> Match, Func<string, HttpResponseMessage> Reply)> _rules = [];

    /// <summary>Every SOAP body sent, in order — for asserting what was put on the wire.</summary>
    public List<string> Requests { get; } = [];

    public ScriptedHttpHandler When(Func<string, bool> match, Func<string, HttpResponseMessage> reply)
    {
        _rules.Add((match, reply));
        return this;
    }

    public ScriptedHttpHandler When(string bodyContains, HttpStatusCode status, string xml) =>
        When(body => body.Contains(bodyContains, StringComparison.OrdinalIgnoreCase), _ => Soap(status, xml));

    public static HttpResponseMessage Soap(HttpStatusCode status, string xml) =>
        new(status) { Content = new StringContent(xml, Encoding.UTF8, "application/soap+xml") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        lock (Requests) Requests.Add(body);

        foreach (var (match, reply) in _rules)
        {
            if (match(body)) return reply(body);
        }

        // Unmatched requests fail loudly. Returning a bland 200 would let a test "pass" against an
        // exchange the client never actually performed.
        return Soap(HttpStatusCode.NotImplemented, "<unmatched/>");
    }
}
