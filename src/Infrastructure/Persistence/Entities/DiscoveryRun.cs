namespace PatchManagement.Persistence.Entities;

/// <summary>
/// One execution of a network sweep, kept as provenance: what was asked for, what was refused, and
/// what was actually probed.
///
/// <para><see cref="RefusedRanges"/> is why this table exists rather than a counter somewhere. A
/// sweep that was not permitted to run and a sweep that ran and found nothing both end with an empty
/// host list, and the difference between them is the difference between a coverage gap and a clean
/// result. The refusal, with its reason, is recorded so that difference survives into the report.</para>
/// </summary>
public sealed class DiscoveryRun
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }

    public DateTimeOffset StartedAt { get; set; }

    /// <summary>Null while the run is open; set when it reaches a terminal outcome.</summary>
    public DateTimeOffset? CompletedAt { get; set; }

    /// <summary>
    /// Kebab-case wire value mirroring <c>Contracts.Discovery.SweepOutcome</c>, plus <c>running</c>
    /// for the open state. Pinned against the CHECK constraint by <c>SweepVocabularyTests</c>.
    /// </summary>
    public string Outcome { get; set; } = DiscoveryRunOutcomes.Running;

    /// <summary>The ranges as requested, verbatim, so a refusal can be explained afterwards.</summary>
    public string RequestedRanges { get; set; } = "[]";

    public string RequestedPorts { get; set; } = "[]";

    /// <summary><c>[{ "range": "...", "reason": "..." }]</c>. Empty on a permitted sweep.</summary>
    public string RefusedRanges { get; set; } = "[]";

    public int AddressesProbed { get; set; }
    public int HostsFound { get; set; }

    /// <summary>Diagnostic detail. Never a credential and never remote output.</summary>
    public string? Detail { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// The stored vocabulary for <see cref="DiscoveryRun.Outcome"/>.
///
/// <para>These are the DB-side copy of <c>SweepOutcome</c>'s wire names. Two copies of a vocabulary
/// fork silently — Phase 5 learned that as a Postgres <c>23514</c> at ingest time, after a connector
/// had been written, reviewed and merged — so <c>SweepVocabularyTests</c> pins these against both
/// the enum and the live CHECK constraint.</para>
/// </summary>
public static class DiscoveryRunOutcomes
{
    /// <summary>The run is open. Not a <c>SweepOutcome</c> — a sweep in flight has no outcome yet.</summary>
    public const string Running = "running";

    public const string Ok = "ok";
    public const string RefusedByPolicy = "refused-by-policy";
    public const string InvalidRange = "invalid-range";

    /// <summary>The run did not complete. Not a <c>SweepOutcome</c> either: the sweeper returns a
    /// typed result for every outcome it models, so this covers a run abandoned outside it.</summary>
    public const string Failed = "failed";

    public static readonly IReadOnlyList<string> All =
        [Running, Ok, RefusedByPolicy, InvalidRange, Failed];

    /// <summary>The subset that corresponds one-to-one with <c>SweepOutcome</c> members.</summary>
    public static readonly IReadOnlyList<string> SweepOutcomes = [Ok, RefusedByPolicy, InvalidRange];
}
