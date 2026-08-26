using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Discovery.Store;

namespace PatchManagement.Discovery.Correlation;

/// <summary>
/// Cross-references discovered hosts against every registered evidence source.
/// </summary>
internal sealed class CorrelationService(
    IEnumerable<IAssetEvidenceSource> sources,
    IDiscoveryStore store,
    ILogger<CorrelationService> logger) : ICorrelationService
{
    private readonly IReadOnlyList<IAssetEvidenceSource> _sources = [.. sources];

    public async Task<CorrelationSummary> CorrelateAsync(Guid discoveryRunId, CancellationToken ct)
    {
        var assets = await store.AssetsFromRunAsync(discoveryRunId, ct).ConfigureAwait(false);
        var recorded = 0;

        foreach (var (assetId, address) in assets)
        {
            foreach (var source in _sources)
            {
                var lookup = await source.LookupAsync(address, ct).ConfigureAwait(false);

                // BOTH outcomes are written. An absence is not the lack of a row — it is a row
                // saying a source was consulted and did not hold this host, and it is what makes an
                // unmanaged flag explainable afterwards rather than only at the moment it was
                // computed (CLAUDE.md 4.6).
                await store
                    .AppendEvidenceAsync(assetId, source.Source, lookup.Present, address, lookup.Detail, ct)
                    .ConfigureAwait(false);
                recorded++;
            }
        }

        logger.LogInformation(
            "Correlated {Assets} asset(s) from run {RunId} against {Sources} source(s).",
            assets.Count, discoveryRunId, _sources.Count);

        return new CorrelationSummary
        {
            AssetsCorrelated = assets.Count,
            EvidenceRecorded = recorded,
            SourcesConsulted = _sources.Count,
        };
    }

    public Task<IReadOnlyList<UnmanagedAsset>> UnmanagedAsync(CancellationToken ct) =>
        store.UnmanagedAsync(ct);
}
