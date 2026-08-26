namespace PatchManagement.Contracts.Discovery;

/// <summary>
/// Runs a sweep and persists what it found: a <c>discovery_runs</c> row for provenance, one
/// <c>assets</c> candidate per reachable endpoint, and the <c>asset_evidence</c> that explains each.
///
/// <para><b>Nothing invokes this yet</b> — no job, no endpoint. That is the same shape as
/// <c>ContentSyncService</c> and needs the same decision (owner: Phase 11, scheduling). It is
/// recorded rather than left to be discovered, because a module that persists nothing until
/// something calls it looks identical to one that does not work.</para>
/// </summary>
public interface IDiscoveryService
{
    Task<DiscoveryRunSummary> RunAsync(SweepRequest request, CancellationToken ct);
}

/// <summary>
/// What one run did. <see cref="AssetIds"/> is ordered to match the candidates as persisted, and is
/// the value criterion (h) is asserted on: a re-run must return <b>the same ids</b>, not merely the
/// same count.
/// </summary>
public sealed record DiscoveryRunSummary
{
    /// <summary>The <c>discovery_runs</c> row. Written even when the sweep is refused.</summary>
    public required Guid RunId { get; init; }

    public required SweepOutcome Outcome { get; init; }

    public required int AddressesProbed { get; init; }

    /// <summary>Candidate asset ids, ascending. Empty when the sweep was refused.</summary>
    public required IReadOnlyList<Guid> AssetIds { get; init; }

    public bool Succeeded => Outcome == SweepOutcome.Ok;
}
