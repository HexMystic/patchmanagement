namespace PatchManagement.Contracts.Discovery;

/// <summary>
/// Cross-references discovered hosts against every registered <see cref="IAssetEvidenceSource"/> and
/// surfaces the ones present on the network but in nobody's inventory — the Phase 4 differentiator
/// (<c>DIFFERENTIATORS.md</c> §2), and criterion (f).
/// </summary>
public interface ICorrelationService
{
    /// <summary>
    /// Asks every source about every address the given run found, appending one evidence row per
    /// (asset, source) — <b>including the absences</b>, which are the load-bearing half.
    /// </summary>
    Task<CorrelationSummary> CorrelateAsync(Guid discoveryRunId, CancellationToken ct);

    /// <summary>
    /// Assets seen by discovery and corroborated by no other source, each carrying the evidence that
    /// explains the flag.
    /// </summary>
    Task<IReadOnlyList<UnmanagedAsset>> UnmanagedAsync(CancellationToken ct);
}

/// <summary>What one correlation pass did.</summary>
public sealed record CorrelationSummary
{
    public required int AssetsCorrelated { get; init; }

    /// <summary>Evidence rows appended, sightings and absences together.</summary>
    public required int EvidenceRecorded { get; init; }

    public required int SourcesConsulted { get; init; }
}

/// <summary>
/// A host on the network that no inventory claims.
///
/// <para><see cref="Evidence"/> is not decoration — CLAUDE.md §4.6 requires the flag to be
/// explainable, and an unmanaged finding an operator cannot audit is one they will not act on. The
/// list carries the sighting that found it AND every source that was asked and said no.</para>
/// </summary>
public sealed record UnmanagedAsset
{
    public required Guid AssetId { get; init; }
    public required string Address { get; init; }
    public required IReadOnlyList<EvidenceEntry> Evidence { get; init; }

    /// <summary>Sources consulted that did not hold this host, ascending.</summary>
    public IReadOnlyList<string> AbsentFrom =>
        [.. Evidence.Where(e => !e.Present).Select(e => e.Source).Distinct().Order(StringComparer.Ordinal)];
}

/// <summary>One recorded observation, as it will be read back in a report.</summary>
public sealed record EvidenceEntry(
    string Source, bool Present, DateTimeOffset ObservedAt, string? Address, string? Detail);
