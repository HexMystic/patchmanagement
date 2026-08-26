using System.Collections.Concurrent;
using PatchManagement.Discovery.Sweep;

namespace PatchManagement.Discovery.Tests.Fakes;

/// <summary>
/// A probe that opens no socket and records every address it was asked about.
///
/// <para><see cref="Attempts"/> is the load-bearing part. A guard that refuses a range is only
/// proven by the absence of probes against it — asserting on the returned host list would pass
/// just as well against a sweep that probed the whole range and happened to find nothing, which is
/// precisely the confusion <see cref="Contracts.Discovery.SweepOutcome"/> exists to prevent.</para>
/// </summary>
internal sealed class FakePortProbe : IPortProbe
{
    private readonly HashSet<(string Address, int Port)> _open;

    public FakePortProbe(params (string Address, int Port)[] open) => _open = [.. open];

    /// <summary>Every (address, port) this probe was asked to attempt, in call order.</summary>
    public ConcurrentQueue<(string Address, int Port)> Attempts { get; } = new();

    public IReadOnlyCollection<string> AddressesAttempted =>
        Attempts.Select(a => a.Address).Distinct(StringComparer.Ordinal).ToList();

    public Task<PortProbeResult> ProbeAsync(string address, int port, TimeSpan timeout, CancellationToken ct)
    {
        Attempts.Enqueue((address, port));

        return Task.FromResult(_open.Contains((address, port))
            ? new PortProbeResult(true, TimeSpan.FromMilliseconds(3))
            : PortProbeResult.Closed);
    }
}
