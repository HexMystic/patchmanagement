using PatchManagement.Discovery.Sweep;

namespace PatchManagement.Discovery.IntegrationTests.Fakes;

/// <summary>
/// A probe that opens no socket and reports a fixed set of (address, port) pairs as open.
///
/// <para>Deliberately narrower than the unit suite's fake of the same name: the store tests care
/// only about <i>what the sweep found</i>, never about which addresses were attempted, so this one
/// keeps no attempt log. They are not a forked copy of one type — the unit suite's version exists to
/// prove a guard refused to probe, which is a question this project never asks.</para>
///
/// <para>The store tests use a fake rather than real listeners so a failure means the store is
/// wrong, not that a socket misbehaved.</para>
/// </summary>
internal sealed class FakePortProbe(params (string Address, int Port)[] open) : IPortProbe
{
    private readonly HashSet<(string, int)> _open = [.. open];

    public Task<PortProbeResult> ProbeAsync(
        string address, int port, TimeSpan timeout, CancellationToken ct) =>
        Task.FromResult(_open.Contains((address, port))
            ? new PortProbeResult(true, TimeSpan.FromMilliseconds(2))
            : PortProbeResult.Closed);
}
