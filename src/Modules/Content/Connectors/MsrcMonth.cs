namespace PatchManagement.Content.Connectors;

/// <summary>
/// One entry from the MSRC monthly index (<c>cvrf/v3.0/updates</c>): the month's id and the URL of
/// its CVRF document. Microsoft publishes per month, so a month is the unit a sync fetches.
/// </summary>
public sealed record MsrcMonth(string Id, string CvrfUrl);
