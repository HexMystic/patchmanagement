using Microsoft.Extensions.Logging;
using PatchManagement.Connectors;
using PatchManagement.Connectors.Facts;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Contracts.States;
using PatchManagement.Discovery.Store;

namespace PatchManagement.Discovery.Inventory;

/// <summary>
/// Inventories an asset over the connector and records the result honestly.
///
/// <para><b>Connectivity is probed FIRST, and that ordering is the whole of criterion (e).</b>
/// <see cref="EndpointFactsCollector"/> reports every failure as a <c>FactsCollectionException</c>,
/// so a caller that simply wrapped it in a try/catch would record <c>scan-failed</c> for a rejected
/// credential, an unreachable host and a genuinely broken command alike. Those are three different
/// problems with three different owners: <c>auth-failed</c> sends someone to whoever holds
/// credentials, <c>unreachable</c> to the network team, <c>scan-failed</c> to whoever owns this
/// software. Conflating them wastes the hour the report is read in (HARD-PROBLEMS #12).</para>
///
/// <para><see cref="IEndpointConnector.TestConnectivityAsync"/> already answers that question in the
/// connector's own vocabulary and budgets reachability separately from authentication. Asking it
/// first is what turns an exception back into a typed outcome — so the mapping is read from what the
/// endpoint did, not inferred from which exception escaped.</para>
///
/// <para><b>The connector comes from the REGISTRY, and the facts collector is built around it per
/// target.</b> Not a style choice: <c>EndpointFactsCollector</c> takes a single
/// <see cref="IEndpointConnector"/>, and the Connectors module registers two of them, so resolving
/// the collector from DI hands it whichever was registered last — <c>WinRmConnector</c>, whose facts
/// path is deferred to D-302 and returns <c>Unsupported</c> by design. Observed, not theorised: a
/// container built from <c>AddConnectorsModule</c> resolves
/// <c>EndpointFactsCollector</c> with <c>COLLECTOR_USES=WinRmConnector</c>, and every SSH inventory
/// through it came back <c>AuthFailed</c>. Selecting by protocol is what the registry exists for.</para>
/// </summary>
internal sealed class InventoryService(
    IEndpointConnectorRegistry connectors,
    IDiscoveryStore store,
    ILogger<InventoryService> logger) : IInventoryService
{
    public async Task<InventoryResult> InventoryAsync(
        Guid assetId, EndpointTarget target, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);

        var connector = connectors.For(target);
        var facts = new EndpointFactsCollector(connectors);

        var connectivity = await connector.TestConnectivityAsync(target, ct).ConfigureAwait(false);

        if (!connectivity.IsReachable)
        {
            // ToEndpointState() is the connector's own frozen mapping (ConnectorOutcomeMapping),
            // reused rather than restated so the two cannot drift.
            var state = connectivity.ToEndpointState()!.Value;

            logger.LogInformation(
                "Inventory of {AssetId} stopped at connectivity: {Outcome} -> {State}.",
                assetId, connectivity.Outcome, state);

            await store.RecordFailureAsync(assetId, state, ct).ConfigureAwait(false);

            return new InventoryResult
            {
                Outcome = connectivity.Outcome,
                State = state,
                // The connector's own diagnostic, which is a compile-time constant on every
                // path — never built from remote output (see ConnectorReason).
                Detail = connectivity.Detail,
            };
        }

        try
        {
            var collected = await facts.CollectAsync(target, ct).ConfigureAwait(false);

            var packages = await store
                .ReplacePackagesAsync(assetId, collected, ct)
                .ConfigureAwait(false);

            return new InventoryResult
            {
                Outcome = ConnectorOutcome.Ok,
                // Null: a successful inventory is NOT a state transition. The frozen machine has no
                // "inventoried" state and assessment owns the compliance ones. See InventoryResult.
                State = null,
                PackagesRecorded = packages,
                OsFamily = collected.OsFamily,
                OsId = collected.OsId,
                OsVersion = collected.OsVersion,
            };
        }
        catch (FactsCollectionException)
        {
            // Reached and authenticated, then the fact-gathering itself failed. That is genuinely
            // scan-failed: our problem, not the network's and not the credential's.
            logger.LogWarning("Inventory of {AssetId} reached the host but could not gather facts.", assetId);

            await store.RecordFailureAsync(assetId, EndpointState.ScanFailed, ct).ConfigureAwait(false);

            return new InventoryResult
            {
                Outcome = ConnectorOutcome.ProtocolError,
                State = EndpointState.ScanFailed,
                Detail = ConnectorReason.FactsCommandFailed,
            };
        }
    }
}
