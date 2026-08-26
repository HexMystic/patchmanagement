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

    /// <summary>
    /// Records a successful inventory: OS identity onto the asset, <c>managed = true</c>, and the
    /// package set replaced wholesale. Returns the number of packages written.
    ///
    /// <para><b>Replace, not merge.</b> A package set is a snapshot of what is installed NOW, so
    /// merging would leave a package that had been REMOVED sitting in the inventory forever — and
    /// Phase 6 would then assess a host against software it no longer has. Removal is exactly as
    /// important as installation to a patch product.</para>
    /// </summary>
    Task<int> ReplacePackagesAsync(
        Guid assetId, Contracts.Connectors.EndpointFacts facts, CancellationToken ct);

    /// <summary>
    /// Records that inventory could not be completed, moving the asset to an honest failure state.
    /// Never collapses "couldn't check" into compliant (HARD-PROBLEMS #8).
    /// </summary>
    Task RecordFailureAsync(
        Guid assetId, Contracts.States.EndpointState state, CancellationToken ct);
}
