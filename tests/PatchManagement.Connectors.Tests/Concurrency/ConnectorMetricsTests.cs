using System.Diagnostics.Metrics;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors.Concurrency;

namespace PatchManagement.Connectors.Tests.Concurrency;

/// <summary>
/// Saturation has to be observable from outside the process. During a wave the question an operator
/// asks is "is this stalled or just slow", and the only honest answer comes from the connection
/// budget — which means it has to reach a metrics backend, not just a debugger.
/// </summary>
public sealed class ConnectorMetricsTests
{
    private static readonly Guid Tenant = Guid.Parse("dddddddd-0000-0000-0000-000000000004");
    private const string Host = "localhost:2201";

    [Fact]
    public async Task Acquiring_and_releasing_emits_the_active_connection_gauge()
    {
        // A meter unique to this test. Meters are process-global and matched by name, so without
        // this the parallel suite's other governors publish into the same stream and the assertions
        // below measure the whole test run rather than this governor.
        var meter = $"{ConnectorMetrics.MeterName}.{Guid.NewGuid():N}";
        var measurements = new List<(string Instrument, long Value)>();
        using var listener = Listen(measurements, meter);

        using var governor = new SemaphoreConnectionGovernor(
            Options.Create(new ConnectorConcurrencyOptions()), meter);

        var lease = await governor.AcquireAsync(Tenant, Host, CancellationToken.None);
        await lease.DisposeAsync();

        var active = measurements.Where(m => m.Instrument == "connections.active").Select(m => m.Value).ToList();

        Assert.Contains(1, active);   // acquired
        Assert.Contains(-1, active);  // released
        Assert.Equal(0, active.Sum()); // and it balances, so the gauge does not drift
    }

    [Fact]
    public async Task A_refused_TryAcquire_is_counted_as_a_rejection()
    {
        var meter = $"{ConnectorMetrics.MeterName}.{Guid.NewGuid():N}";
        var measurements = new List<(string Instrument, long Value)>();
        using var listener = Listen(measurements, meter);

        using var governor = new SemaphoreConnectionGovernor(
            Options.Create(new ConnectorConcurrencyOptions { GlobalMaxConnections = 1 }), meter);

        Assert.True(governor.TryAcquire(Tenant, Host, out var held));
        Assert.False(governor.TryAcquire(Tenant, Host, out _));

        // Load shedding that is invisible looks exactly like work that was never requested.
        Assert.Equal(1, measurements.Where(m => m.Instrument == "connections.rejected").Sum(m => m.Value));

        await held!.DisposeAsync();
    }

    private static MeterListener Listen(List<(string, long)> sink, string meterName)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == meterName) l.EnableMeasurementEvents(instrument);
            },
        };

        listener.SetMeasurementEventCallback<int>((instrument, value, _, _) =>
        {
            lock (sink) sink.Add((instrument.Name, value));
        });
        listener.SetMeasurementEventCallback<long>((instrument, value, _, _) =>
        {
            lock (sink) sink.Add((instrument.Name, value));
        });

        listener.Start();
        return listener;
    }
}
