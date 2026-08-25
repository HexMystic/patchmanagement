namespace PatchManagement.Content.Connectors;

/// <summary>
/// The paging counters NVD puts on every 2.0 response. They were read by nothing until Phase 5
/// criterion (b): a response spanning more than one page was truncated to the first and the sync
/// reported <c>ok</c> — the same silent-truncation class as the invented envelopes, arriving by a
/// different route.
/// </summary>
/// <param name="StartIndex">Offset of this page.</param>
/// <param name="ResultsPerPage">How many records this page actually carried.</param>
/// <param name="TotalResults">How many the whole window holds.</param>
public sealed record NvdPaging(int StartIndex, int ResultsPerPage, int TotalResults)
{
    /// <summary>Where the next request starts, or null when this page was the last one.</summary>
    public int? NextStartIndex =>
        ResultsPerPage > 0 && StartIndex + ResultsPerPage < TotalResults
            ? StartIndex + ResultsPerPage
            : null;
}
