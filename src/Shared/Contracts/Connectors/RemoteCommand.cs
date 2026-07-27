using System.Text;

namespace PatchManagement.Contracts.Connectors;

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

    /// <summary>
    /// Keeps <see cref="CommandLine"/> out of the generated <c>ToString()</c>.
    ///
    /// <para>A record prints every property, so <c>LogInformation("{Command}", command)</c> would
    /// render the command line verbatim — and a command line is the single most likely place for a
    /// secret to be sitting: a password piped to <c>sudo -S</c>, an <c>--api-key</c>, a
    /// <c>curl -u user:pass</c>. The connector cannot know what a caller embedded, so it declines to
    /// print it at all (ADR 0012 decision C).</para>
    ///
    /// <para>The length is kept because it is diagnostically useful and discloses nothing: it
    /// distinguishes "the command was empty" from "the command was not what I expected", which is
    /// most of what a reader wants from a <c>ToString()</c> anyway.</para>
    /// </summary>
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("CommandLine = <redacted:").Append(CommandLine?.Length ?? 0).Append(" chars>");
        builder.Append(", RequiresElevation = ").Append(RequiresElevation);
        builder.Append(", Timeout = ").Append(Timeout);
        builder.Append(", IdempotencyKey = ").Append(IdempotencyKey ?? "<none>");
        builder.Append(", ExpectsOnwardAuth = ").Append(ExpectsOnwardAuth);
        return true;
    }
}
