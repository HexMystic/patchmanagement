using PatchManagement.Contracts.Discovery;

namespace PatchManagement.Discovery.Store;

/// <summary>
/// Persists what a sweep observed. Every write is tenant-scoped through the RLS-intercepted
/// <c>AppDbContext</c>, so the database refuses a cross-tenant write rather than trusting the caller
/// to pass the right id.
/// </summary>
internal interface IDiscoveryStore
{
    /// <summary>Opens a <c>discovery_runs</c> row before anything is probed, and returns its id.</summary>
    Task<Guid> OpenRunAsync(SweepRequest request, CancellationToken ct);

    /// <summary>
    /// Records the outcome and closes the run. Called for a refused sweep too — a refusal is
    /// provenance, and a run that recorded nothing would be indistinguishable from one that never
    /// happened.
    /// </summary>
    Task CloseRunAsync(Guid runId, SweepResult result, int hostsFound, CancellationToken ct);

    /// <summary>
    /// Inserts-or-updates one candidate per (address, open port) and appends the evidence that
    /// explains each. Returns the asset ids, ascending.
    ///
    /// <para><b>The ids must be stable across runs</b> (criterion h). Findings, packages and
    /// evidence all hang off the asset id, so an id that changes on re-discovery orphans everything
    /// that referenced it — which no row count would reveal.</para>
    /// </summary>
    Task<IReadOnlyList<Guid>> UpsertCandidatesAsync(
        Guid runId, IReadOnlyList<DiscoveredHost> hosts, CancellationToken ct);
}
