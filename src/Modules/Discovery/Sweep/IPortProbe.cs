namespace PatchManagement.Discovery.Sweep;

/// <summary>
/// One bounded TCP connect attempt against an address/port.
///
/// <para>A seam, not an abstraction for its own sake: it is what lets the sweep be unit-tested
/// without opening a single socket. That matters more here than in most modules — the sweep is the
/// first feature in this product that can contact an arbitrary address, so a suite that reached the
/// network to prove the sweep works would be exercising the behaviour NEVER #4 forbids in order to
/// test the guard against it.</para>
/// </summary>
internal interface IPortProbe
{
    /// <summary>
    /// Attempts a TCP connection within <paramref name="timeout"/>. Never throws for an unreachable
    /// host — a closed port is an expected observation for a sweep, not a fault.
    /// </summary>
    Task<PortProbeResult> ProbeAsync(string address, int port, TimeSpan timeout, CancellationToken ct);
}

/// <summary>Whether the port answered, and how quickly.</summary>
internal readonly record struct PortProbeResult(bool Open, TimeSpan Elapsed)
{
    public static PortProbeResult Closed => new(false, TimeSpan.Zero);
}
