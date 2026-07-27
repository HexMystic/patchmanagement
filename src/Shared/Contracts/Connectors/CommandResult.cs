namespace PatchManagement.Contracts.Connectors;

/// <summary>
/// The typed result of a remote command — failure is modelled, not thrown (CLAUDE.md §5).
///
/// NOTE (CLAUDE.md NEVER #3): a zero <see cref="ExitCode"/> is a <i>hint</i>, never proof that a
/// patch was applied. Verification re-observes endpoint state in a later phase; this type only
/// reports what the command returned.
/// </summary>
public sealed record CommandResult
{
    public required ConnectorOutcome Outcome { get; init; }

    /// <summary>Process exit code, or <c>null</c> when the command never ran (non-Ok outcome).</summary>
    public int? ExitCode { get; init; }

    public string StandardOutput { get; init; } = string.Empty;
    public string StandardError { get; init; } = string.Empty;

    /// <summary>Wall-clock time spent, for instrumentation and timeout diagnostics.</summary>
    public TimeSpan Duration { get; init; }

    /// <summary>Human-readable detail for non-Ok outcomes (never contains secret material).</summary>
    public string? Detail { get; init; }

    public bool Succeeded => Outcome == ConnectorOutcome.Ok;

    public static CommandResult Ran(int exitCode, string stdout, string stderr, TimeSpan duration) => new()
    {
        Outcome = ConnectorOutcome.Ok,
        ExitCode = exitCode,
        StandardOutput = stdout,
        StandardError = stderr,
        Duration = duration,
    };

    public static CommandResult Failed(ConnectorOutcome outcome, string detail, TimeSpan duration) => new()
    {
        Outcome = outcome,
        Detail = detail,
        Duration = duration,
    };
}
