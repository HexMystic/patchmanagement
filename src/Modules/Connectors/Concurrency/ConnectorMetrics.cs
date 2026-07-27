using System.Diagnostics.Metrics;

namespace PatchManagement.Connectors.Concurrency;

/// <summary>
/// Instruments the connection budget. At the 10,000-endpoint target the wall is concurrent
/// connections, so "how saturated is the governor" is the number an operator watches during a wave —
/// and the one that explains a deployment that is running but not progressing.
///
/// <para>Deliberately counters and a histogram rather than log lines: saturation is a continuous
/// quantity sampled over time, and a log entry per acquire would produce an enormous volume of text
/// that still could not answer "what was the queue depth at 14:03".</para>
///
/// <para>The names carry no tenant id. Cardinality is the reason — a per-tenant dimension on a
/// 10,000-endpoint estate multiplies every series by the tenant count and will take a metrics
/// backend down. Per-tenant depth is available synchronously from the governor when something needs
/// it.</para>
/// </summary>
internal sealed class ConnectorMetrics : IDisposable
{
    public const string MeterName = "PatchManagement.Connectors";

    private readonly Meter _meter;
    private readonly UpDownCounter<int> _active;
    private readonly UpDownCounter<int> _waiting;
    private readonly Counter<long> _rejected;
    private readonly Histogram<double> _waitDuration;

    /// <summary>
    /// <paramref name="meterName"/> overrides the meter name so tests can observe one governor in
    /// isolation. A <see cref="Meter"/> is process-global and matched by NAME, so two governors
    /// running concurrently — which is the normal state of a parallel test suite — publish into the
    /// same stream and each test sees the others' measurements. That produces a suite which passes
    /// individually and fails together, the worst kind to diagnose.
    /// </summary>
    public ConnectorMetrics(string? meterName = null)
    {
        _meter = new Meter(meterName ?? MeterName);
        _active = _meter.CreateUpDownCounter<int>(
            "connections.active", "connections", "Endpoint connections currently held.");
        _waiting = _meter.CreateUpDownCounter<int>(
            "connections.waiting", "operations", "Operations blocked waiting for a connection slot.");
        _rejected = _meter.CreateCounter<long>(
            "connections.rejected", "operations", "TryAcquire calls refused because no slot was free.");
        _waitDuration = _meter.CreateHistogram<double>(
            "connection.wait.duration", "ms", "Time spent waiting for a connection slot.");
    }

    public void Acquired() => _active.Add(1);
    public void Released() => _active.Add(-1);
    public void WaitStarted() => _waiting.Add(1);
    public void WaitEnded() => _waiting.Add(-1);
    public void Rejected() => _rejected.Add(1);
    public void Waited(double milliseconds) => _waitDuration.Record(milliseconds);

    public void Dispose() => _meter.Dispose();
}
