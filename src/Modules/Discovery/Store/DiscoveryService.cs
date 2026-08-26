using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Discovery;

namespace PatchManagement.Discovery.Store;

/// <summary>
/// Sweeps, then persists — the whole of a discovery run.
///
/// <para><b>The run row is opened BEFORE the sweep and closed after, including when the sweep is
/// refused.</b> Recording only successful runs would make "we were refused" indistinguishable from
/// "we never tried", and the refusal carries the reason an operator needs. It is the same reason the
/// sweep itself returns a refusal outcome rather than an empty host list.</para>
/// </summary>
internal sealed class DiscoveryService(
    INetworkSweeper sweeper,
    IDiscoveryStore store,
    ILogger<DiscoveryService> logger) : IDiscoveryService
{
    public async Task<DiscoveryRunSummary> RunAsync(SweepRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        var runId = await store.OpenRunAsync(request, ct).ConfigureAwait(false);
        var result = await sweeper.ScanAsync(request, ct).ConfigureAwait(false);

        IReadOnlyList<Guid> assetIds = [];
        if (result.Succeeded)
        {
            assetIds = await store
                .UpsertCandidatesAsync(runId, result.Hosts, ct)
                .ConfigureAwait(false);
        }
        else
        {
            logger.LogWarning(
                "Discovery run {RunId} did not sweep: {Outcome}, {RefusedCount} range(s) refused.",
                runId, result.Outcome, result.Refused.Count);
        }

        await store.CloseRunAsync(runId, result, result.Hosts.Count, ct).ConfigureAwait(false);

        return new DiscoveryRunSummary
        {
            RunId = runId,
            Outcome = result.Outcome,
            AddressesProbed = result.AddressesProbed,
            AssetIds = assetIds,
        };
    }
}
