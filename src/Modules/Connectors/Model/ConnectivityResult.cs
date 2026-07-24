using PatchManagement.Contracts.States;

namespace PatchManagement.Connectors.Model;

/// <summary>
/// The result of a connectivity/auth probe. Maps onto the honest state machine so an
/// unreachable or auth-failed host is <b>never</b> recorded as compliant (HARD-PROBLEMS #8).
/// </summary>
public sealed record ConnectivityResult
{
    public required ConnectorOutcome Outcome { get; init; }

    /// <summary>Round-trip latency when the probe reached the host.</summary>
    public TimeSpan? Latency { get; init; }

    /// <summary>Diagnostic detail (never secret material).</summary>
    public string? Detail { get; init; }

    public bool IsReachable => Outcome == ConnectorOutcome.Ok;

    /// <summary>The honest endpoint state this probe implies, or null when reachable.</summary>
    public EndpointState? ToEndpointState() => Outcome.ToEndpointState();

    public static ConnectivityResult Reachable(TimeSpan latency) =>
        new() { Outcome = ConnectorOutcome.Ok, Latency = latency };

    public static ConnectivityResult Failed(ConnectorOutcome outcome, string detail, TimeSpan? latency = null) =>
        new() { Outcome = outcome, Detail = detail, Latency = latency };
}
