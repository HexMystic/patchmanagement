namespace PatchManagement.Contracts.States;

/// <summary>Thrown when an illegal <see cref="EndpointState"/> transition is attempted.</summary>
public sealed class InvalidStateTransitionException(EndpointState from, EndpointState to)
    : InvalidOperationException($"Illegal state transition: {from.ToDbValue()} -> {to.ToDbValue()}.")
{
    public EndpointState From { get; } = from;
    public EndpointState To { get; } = to;
}
