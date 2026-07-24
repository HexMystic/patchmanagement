namespace PatchManagement.Connectors.Model;

/// <summary>
/// A command to run on the endpoint. Idempotency and time-bounding are first-class
/// (CLAUDE.md NEVER #5):
///  * <see cref="IdempotencyKey"/> — when set, the connector serialises concurrent invocations
///    of the same logical operation so a retry after a timeout cannot double-apply.
///  * <see cref="Timeout"/> — an explicit per-command budget; there is never an unbounded wait.
/// </summary>
public sealed record RemoteCommand
{
    /// <summary>The command line to execute (interpreted by the target's shell / PowerShell).</summary>
    public required string CommandLine { get; init; }

    /// <summary>Run with elevation (Linux: <c>sudo -n</c>; Windows: elevated runspace).</summary>
    public bool RequiresElevation { get; init; }

    /// <summary>Explicit time budget for this command. Must be &gt; 0 — no unbounded remote wait.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Optional logical operation key. When set, the connector guarantees the same key is not
    /// executed concurrently (idempotency guard; HARD-PROBLEMS #6). Not a secret.
    /// </summary>
    public string? IdempotencyKey { get; init; }

    /// <summary>
    /// Caller-declared hint that this command authenticates onward to a second host. Combined
    /// with the connector's own static inspection to decide whether a double-hop is required.
    /// </summary>
    public bool ExpectsOnwardAuth { get; init; }
}
