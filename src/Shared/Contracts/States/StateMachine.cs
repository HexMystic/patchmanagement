namespace PatchManagement.Contracts.States;

/// <summary>
/// The endpoint/finding state machine. Transitions are held AS DATA (not hard-coded
/// control flow) so the machine is:
///   * complete — every documented transition is present and frozen in Phase 1;
///   * reopenable — no state is terminal; a closed finding (verified / assessed-compliant
///     / rolled-back) can return to <see cref="EndpointState.AssessedMissing"/>;
///   * extensible — later phases produce a NEW machine via <see cref="With"/> that adds
///     states/transitions WITHOUT removing or altering the frozen ones.
///
/// Business gate (not encoded here): a transition into <see cref="EndpointState.RollbackInProgress"/>
/// additionally requires the finding's patch to be reversible. Structural legality lives
/// here; the reversible check is enforced by the caller (Phases 8/9).
/// </summary>
public sealed class StateMachine
{
    private readonly HashSet<(EndpointState From, EndpointState To)> _transitions;
    private readonly HashSet<EndpointState> _initialStates;

    public StateMachine(
        IEnumerable<(EndpointState From, EndpointState To)> transitions,
        IEnumerable<EndpointState> initialStates)
    {
        _transitions = [.. transitions];
        _initialStates = [.. initialStates];
    }

    /// <summary>States a freshly-created asset/finding may be assigned directly.</summary>
    public static readonly IReadOnlyList<EndpointState> InitialStates =
    [
        EndpointState.Unreachable,
        EndpointState.AuthFailed,
        EndpointState.ScanFailed,
        EndpointState.AssessedCompliant,
        EndpointState.AssessedMissing,
    ];

    /// <summary>The frozen Phase-1 transition table (see docs/phases/phase-1.md).</summary>
    public static readonly IReadOnlyList<(EndpointState From, EndpointState To)> CanonicalTransitions =
    [
        (EndpointState.Unreachable, EndpointState.AuthFailed),
        (EndpointState.Unreachable, EndpointState.ScanFailed),
        (EndpointState.Unreachable, EndpointState.AssessedCompliant),
        (EndpointState.Unreachable, EndpointState.AssessedMissing),

        (EndpointState.AuthFailed, EndpointState.Unreachable),
        (EndpointState.AuthFailed, EndpointState.ScanFailed),
        (EndpointState.AuthFailed, EndpointState.AssessedCompliant),
        (EndpointState.AuthFailed, EndpointState.AssessedMissing),

        (EndpointState.ScanFailed, EndpointState.Unreachable),
        (EndpointState.ScanFailed, EndpointState.AuthFailed),
        (EndpointState.ScanFailed, EndpointState.AssessedCompliant),
        (EndpointState.ScanFailed, EndpointState.AssessedMissing),

        (EndpointState.AssessedCompliant, EndpointState.AssessedMissing),
        (EndpointState.AssessedCompliant, EndpointState.Unreachable),
        (EndpointState.AssessedCompliant, EndpointState.AuthFailed),
        (EndpointState.AssessedCompliant, EndpointState.ScanFailed),

        (EndpointState.AssessedMissing, EndpointState.DeployInProgress),
        (EndpointState.AssessedMissing, EndpointState.AssessedCompliant),

        (EndpointState.DeployInProgress, EndpointState.PendingReboot),
        (EndpointState.DeployInProgress, EndpointState.DeployFailed),
        (EndpointState.DeployInProgress, EndpointState.Verified),

        (EndpointState.PendingReboot, EndpointState.Verified),
        (EndpointState.PendingReboot, EndpointState.DeployFailed),

        (EndpointState.DeployFailed, EndpointState.RollbackInProgress),
        (EndpointState.DeployFailed, EndpointState.AssessedMissing),

        // Reopen paths: a closed/verified finding can be reopened by new content,
        // drift, reimaging, or a failed health probe.
        (EndpointState.Verified, EndpointState.AssessedMissing),
        (EndpointState.Verified, EndpointState.RollbackInProgress),

        (EndpointState.RollbackInProgress, EndpointState.RolledBack),
        (EndpointState.RollbackInProgress, EndpointState.DeployFailed),

        (EndpointState.RolledBack, EndpointState.AssessedMissing),
    ];

    /// <summary>The canonical, frozen Phase-1 machine.</summary>
    public static readonly StateMachine Canonical = new(CanonicalTransitions, InitialStates);

    /// <summary>
    /// Returns a NEW machine that layers additional transitions/initial states on top of
    /// this one. Existing transitions are never removed — this is the extension point for
    /// later phases (e.g., finer deployment sub-states) that must not alter the frozen set.
    /// </summary>
    public StateMachine With(
        IEnumerable<(EndpointState From, EndpointState To)>? extraTransitions = null,
        IEnumerable<EndpointState>? extraInitialStates = null)
    {
        var t = new HashSet<(EndpointState, EndpointState)>(_transitions);
        if (extraTransitions is not null) t.UnionWith(extraTransitions);
        var i = new HashSet<EndpointState>(_initialStates);
        if (extraInitialStates is not null) i.UnionWith(extraInitialStates);
        return new StateMachine(t, i);
    }

    public bool IsInitial(EndpointState state) => _initialStates.Contains(state);

    public bool CanTransition(EndpointState from, EndpointState to) =>
        _transitions.Contains((from, to));

    /// <summary>Throws <see cref="InvalidStateTransitionException"/> if the transition is illegal.</summary>
    public void AssertTransition(EndpointState from, EndpointState to)
    {
        if (!CanTransition(from, to))
            throw new InvalidStateTransitionException(from, to);
    }

    public IEnumerable<EndpointState> OutgoingFrom(EndpointState from) =>
        _transitions.Where(t => t.From == from).Select(t => t.To);
}
