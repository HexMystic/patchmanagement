namespace PatchManagement.Persistence.Entities;

/// <summary>
/// One observation about an asset from one source, at one time — the record that makes an unmanaged
/// flag <b>explainable</b> (CLAUDE.md §4.6, <c>DIFFERENTIATORS.md</c> §2).
///
/// <para><see cref="Present"/> is what makes this table able to express the claim the differentiator
/// actually makes. "Seen by sweep at IP X" and "checked AD, not there" are both evidence, and it is
/// the second kind — a source consulted and found silent — that turns a reachable host into an
/// unmanaged one. A table that could only record sightings could never explain an absence.</para>
///
/// <para>Rows are appended, never edited: an observation is a fact about a moment, and correcting it
/// means recording a later one. The grants enforce that (SELECT + INSERT only), the same posture
/// <c>audit_log</c> carries.</para>
/// </summary>
public sealed class AssetEvidence
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid AssetId { get; set; }

    /// <summary>Which source produced this observation: discovery / ad / dhcp / inventory.</summary>
    public string Source { get; set; } = AssetSources.Discovery;

    /// <summary>
    /// True when the source held this asset; false when the source was consulted and did not.
    /// A false row is the load-bearing half of an unmanaged finding.
    /// </summary>
    public bool Present { get; set; }

    /// <summary>The sweep that produced it. Required for discovery evidence, null for every other
    /// source — enforced by CHECK, because discovery evidence with no run is not provenance.</summary>
    public Guid? DiscoveryRunId { get; set; }

    public DateTimeOffset ObservedAt { get; set; }

    public string? Address { get; set; }
    public int? Port { get; set; }

    /// <summary>
    /// Source-shaped payload: a DHCP lease id, an AD distinguished name, the observed open-port set.
    /// Never a credential and never the plaintext of a vault item (NEVER #1/#2).
    /// </summary>
    public string? Detail { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

