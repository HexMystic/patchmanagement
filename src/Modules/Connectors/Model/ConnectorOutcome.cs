using PatchManagement.Contracts.States;

namespace PatchManagement.Connectors.Model;

/// <summary>
/// The honest outcome of a connector operation. "Couldn't check" is NEVER collapsed into
/// success (HARD-PROBLEMS #8): unreachable, auth-failed, timeout and double-hop are all
/// first-class, distinct outcomes that map onto the frozen <see cref="EndpointState"/> machine.
/// </summary>
public enum ConnectorOutcome
{
    /// <summary>The operation completed and its result is trustworthy.</summary>
    Ok,

    /// <summary>Host did not accept a connection (refused/no route/DNS/port closed).</summary>
    Unreachable,

    /// <summary>Reached the host but authentication was rejected.</summary>
    AuthFailed,

    /// <summary>The bounded time budget elapsed before completion; the op was cancelled.</summary>
    Timeout,

    /// <summary>
    /// The command needs to authenticate onward to a second host (SMB share, another session)
    /// and no delegation is configured. Surfaced rather than hung (HARD-PROBLEMS #9).
    /// </summary>
    DoubleHopRequired,

    /// <summary>Connected and authenticated, but the protocol/command failed unexpectedly.</summary>
    ProtocolError,
}

public static class ConnectorOutcomeMapping
{
    /// <summary>
    /// Map an outcome onto the honest endpoint state, or <c>null</c> for <see cref="ConnectorOutcome.Ok"/>
    /// (a successful probe does not itself decide compliance — assessment does).
    /// A timeout is treated as <see cref="EndpointState.Unreachable"/> ("couldn't reach in time"),
    /// never as compliant. Protocol/double-hop failures are <see cref="EndpointState.ScanFailed"/>.
    /// </summary>
    public static EndpointState? ToEndpointState(this ConnectorOutcome outcome) => outcome switch
    {
        ConnectorOutcome.Ok => null,
        ConnectorOutcome.Unreachable => EndpointState.Unreachable,
        ConnectorOutcome.Timeout => EndpointState.Unreachable,
        ConnectorOutcome.AuthFailed => EndpointState.AuthFailed,
        ConnectorOutcome.DoubleHopRequired => EndpointState.ScanFailed,
        ConnectorOutcome.ProtocolError => EndpointState.ScanFailed,
        _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Unknown outcome."),
    };
}
