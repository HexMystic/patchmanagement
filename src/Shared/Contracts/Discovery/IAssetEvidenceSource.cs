namespace PatchManagement.Contracts.Discovery;

/// <summary>
/// A place that might know about a host — Active Directory, DHCP leases, an existing managed
/// inventory. Correlation asks every registered source about every discovered address, and records
/// what each one said (Phase 4 criterion (f)).
///
/// <para><b>A source must be able to say "no".</b> That is the whole design constraint. The
/// differentiator is finding machines that are on the network and in <i>nobody's</i> inventory, and
/// an absence is what establishes that — so a lookup returns a definite
/// <see cref="EvidenceLookup.Present"/> rather than a nullable "found it, maybe". A source that
/// could only report sightings could never contribute to an unmanaged finding.</para>
///
/// <para><b>"Could not check" is not "absent."</b> A source that is unreachable must throw rather
/// than return <c>Present = false</c>: an unreachable domain controller would otherwise make every
/// host in the estate look unmanaged, which is HARD-PROBLEMS #8's rule applied to correlation
/// instead of to compliance.</para>
/// </summary>
public interface IAssetEvidenceSource
{
    /// <summary>Which source this is — a value from the asset-source vocabulary (<c>ad</c>, <c>dhcp</c>, <c>inventory</c>).</summary>
    string Source { get; }

    /// <summary>
    /// Whether this source holds the given address. Throws if the source could not be consulted;
    /// never reports an outage as an absence.
    /// </summary>
    Task<EvidenceLookup> LookupAsync(string address, CancellationToken ct);
}

/// <summary>What one source said about one address.</summary>
/// <param name="Present">True when the source holds it; false when the source was consulted and did not.</param>
/// <param name="Detail">Source-shaped corroboration — a lease id, a distinguished name. Never a secret.</param>
public sealed record EvidenceLookup(bool Present, string? Detail = null);
