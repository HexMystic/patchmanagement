using PatchManagement.Contracts.States;
using Xunit;

namespace PatchManagement.Contracts.Tests;

public class StateMachineTests
{
    private static readonly StateMachine Sm = StateMachine.Canonical;

    [Fact]
    public void All_canonical_transitions_are_legal()
    {
        foreach (var (from, to) in StateMachine.CanonicalTransitions)
            Assert.True(Sm.CanTransition(from, to), $"{from} -> {to} should be legal");
    }

    [Theory]
    [InlineData(EndpointState.Unreachable, EndpointState.Verified)]
    [InlineData(EndpointState.AssessedMissing, EndpointState.Verified)]
    [InlineData(EndpointState.RolledBack, EndpointState.Verified)]
    [InlineData(EndpointState.Verified, EndpointState.PendingReboot)]
    [InlineData(EndpointState.PendingReboot, EndpointState.RollbackInProgress)]
    [InlineData(EndpointState.AssessedCompliant, EndpointState.Verified)]
    public void Illegal_transitions_are_rejected_and_throw(EndpointState from, EndpointState to)
    {
        Assert.False(Sm.CanTransition(from, to));
        var ex = Assert.Throws<InvalidStateTransitionException>(() => Sm.AssertTransition(from, to));
        Assert.Equal(from, ex.From);
        Assert.Equal(to, ex.To);
    }

    [Theory]
    [InlineData(EndpointState.Verified)]
    [InlineData(EndpointState.AssessedCompliant)]
    [InlineData(EndpointState.RolledBack)]
    public void Closed_findings_can_reopen_to_assessed_missing(EndpointState closedState)
    {
        // Requirement (c): no state is terminal — a closed/verified finding can reopen.
        Assert.True(Sm.CanTransition(closedState, EndpointState.AssessedMissing));
    }

    [Fact]
    public void No_state_is_a_dead_end()
    {
        foreach (var state in Enum.GetValues<EndpointState>())
            Assert.True(Sm.OutgoingFrom(state).Any(), $"{state} has no outgoing transitions");
    }

    [Fact]
    public void With_extends_without_altering_the_frozen_set()
    {
        var extended = Sm.With([(EndpointState.Verified, EndpointState.PendingReboot)]);

        Assert.True(extended.CanTransition(EndpointState.Verified, EndpointState.PendingReboot));      // added
        Assert.True(extended.CanTransition(EndpointState.Verified, EndpointState.AssessedMissing));    // existing preserved
        Assert.False(Sm.CanTransition(EndpointState.Verified, EndpointState.PendingReboot));           // canonical unchanged
    }

    [Fact]
    public void Rollback_states_are_present_and_frozen()
    {
        Assert.True(Sm.CanTransition(EndpointState.DeployFailed, EndpointState.RollbackInProgress));
        Assert.True(Sm.CanTransition(EndpointState.RollbackInProgress, EndpointState.RolledBack));
    }
}
