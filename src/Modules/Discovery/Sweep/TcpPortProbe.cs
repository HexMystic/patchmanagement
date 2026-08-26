using System.Diagnostics;
using System.Net.Sockets;

namespace PatchManagement.Discovery.Sweep;

/// <summary>
/// The real probe: a TCP connect with an explicit budget, torn down immediately.
///
/// <para>Deliberately a bare connect and nothing more. It sends no payload, speaks no protocol and
/// reads no banner, so what it learns is "something is listening" — exactly what the sweep claims
/// and no more. Banner-based OS classification is criterion (b) and belongs in its own slice, where
/// it can be proven against captured banners instead of guessed at here.</para>
/// </summary>
internal sealed class TcpPortProbe : IPortProbe
{
    public async Task<PortProbeResult> ProbeAsync(
        string address, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        // The budget is linked to the caller's token, so a cancelled sweep stops promptly rather
        // than draining every outstanding probe's timeout first (NEVER #5).
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);

        var started = Stopwatch.GetTimestamp();
        try
        {
            await socket.ConnectAsync(address, port, deadline.Token).ConfigureAwait(false);
            return new PortProbeResult(true, Stopwatch.GetElapsedTime(started));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // caller-initiated cancellation propagates; only the budget is swallowed below
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            // Refused, unroutable, or out of budget. All three mean "no endpoint here", which is an
            // ordinary observation for a sweep — the overwhelmingly common one, in fact.
            return PortProbeResult.Closed;
        }
    }
}
