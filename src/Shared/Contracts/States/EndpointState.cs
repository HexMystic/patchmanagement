namespace PatchManagement.Contracts.States;

/// <summary>
/// The honest lifecycle states shared by assets and findings/deployment-targets.
/// A "couldn't check" outcome is NEVER collapsed into "compliant" — unreachable,
/// auth-failed and scan-failed are first-class, honest failure states.
///
/// This set is FROZEN as of Phase 1 (see docs/phases/phase-1.md). Later phases may
/// ADD states without removing or renaming these; see <see cref="StateMachine"/> for
/// how transitions are extended without altering existing ones.
/// </summary>
public enum EndpointState
{
    Unreachable,
    AuthFailed,
    ScanFailed,
    AssessedCompliant,
    AssessedMissing,
    DeployInProgress,
    DeployFailed,
    PendingReboot,
    Verified,
    RollbackInProgress,
    RolledBack,
}

/// <summary>
/// Canonical kebab-case wire/DB names for <see cref="EndpointState"/>. These strings
/// are the stored contract (DB column values, JSON, API) and must remain stable.
/// </summary>
public static class EndpointStateNames
{
    private static readonly IReadOnlyDictionary<EndpointState, string> ToName =
        new Dictionary<EndpointState, string>
        {
            [EndpointState.Unreachable] = "unreachable",
            [EndpointState.AuthFailed] = "auth-failed",
            [EndpointState.ScanFailed] = "scan-failed",
            [EndpointState.AssessedCompliant] = "assessed-compliant",
            [EndpointState.AssessedMissing] = "assessed-missing",
            [EndpointState.DeployInProgress] = "deploy-in-progress",
            [EndpointState.DeployFailed] = "deploy-failed",
            [EndpointState.PendingReboot] = "pending-reboot",
            [EndpointState.Verified] = "verified",
            [EndpointState.RollbackInProgress] = "rollback-in-progress",
            [EndpointState.RolledBack] = "rolled-back",
        };

    private static readonly IReadOnlyDictionary<string, EndpointState> FromNameMap =
        ToName.ToDictionary(kv => kv.Value, kv => kv.Key);

    public static string ToDbValue(this EndpointState state) =>
        ToName.TryGetValue(state, out var name)
            ? name
            : throw new ArgumentOutOfRangeException(nameof(state), state, "No canonical name for state.");

    public static EndpointState FromDbValue(string value) =>
        FromNameMap.TryGetValue(value, out var state)
            ? state
            : throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown state name.");
}
