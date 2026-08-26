namespace PatchManagement.Discovery;

/// <summary>
/// Budgets and bounds for a network sweep. Bound to configuration section <c>Discovery:Sweep</c>.
///
/// <para>Every value here exists to keep a sweep <b>bounded</b> (CLAUDE.md NEVER #5). A sweep is
/// the one operation in this product whose cost is set by an operator typing a prefix length: a
/// <c>/8</c> is 16.7 million addresses, and at four ports each that is 67 million connect attempts
/// from one request. Connection concurrency, not the database, is the wall at 10,000 endpoints
/// (CLAUDE.md §2), so an unbounded sweep does not merely run slowly — it starves everything else
/// the process is doing.</para>
/// </summary>
public sealed class DiscoverySweepOptions
{
    public const string SectionName = "Discovery:Sweep";

    /// <summary>
    /// Ports probed on each address when the request does not name its own. These are the
    /// management protocols this product speaks (CLAUDE.md §2) — SSH, WinRM HTTP, WinRM HTTPS, SMB
    /// — not a general port scan. Discovery looks for endpoints it could manage, and probing beyond
    /// that would be collecting information the product has no use for.
    /// </summary>
    public IList<int> ManagementPorts { get; set; } = [22, 5985, 5986, 445];

    /// <summary>
    /// Largest number of addresses a single requested range may expand to. Default 65,536 (a
    /// <c>/16</c>). A range above the cap is refused <b>by name</b> rather than truncated: sweeping
    /// the first 65,536 addresses of a <c>/8</c> and reporting success would tell an operator their
    /// estate contains what the first 0.4% of it contains.
    /// </summary>
    public int MaxHostsPerRange { get; set; } = 65_536;

    /// <summary>Ceiling on in-flight probes across the whole sweep.</summary>
    public int MaxConcurrentProbes { get; set; } = 64;

    /// <summary>
    /// Per-probe TCP connect budget. Short on purpose, and for the reason
    /// <c>ConnectorTimeoutOptions</c> already documents: reaching a host either completes in a
    /// moment or the host is not reachable. A sweep over a dead subnet costs addresses x ports x
    /// this number, so it is the single value that decides whether a sweep is minutes or hours.
    /// </summary>
    public TimeSpan ProbeTimeout { get; set; } = TimeSpan.FromSeconds(2);

    public void Validate()
    {
        if (ManagementPorts.Count == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ManagementPorts), ManagementPorts,
                "A sweep with no ports to probe would report every host unreachable.");
        }

        if (ManagementPorts.Any(p => p is < 1 or > 65535))
        {
            throw new ArgumentOutOfRangeException(
                nameof(ManagementPorts), ManagementPorts, "Ports must be within 1-65535.");
        }

        if (MaxHostsPerRange < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxHostsPerRange), MaxHostsPerRange, "A sweep must be able to probe at least one address.");
        }

        if (MaxConcurrentProbes < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxConcurrentProbes), MaxConcurrentProbes, "At least one probe must be allowed in flight.");
        }

        if (ProbeTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ProbeTimeout), ProbeTimeout,
                "Every remote operation must be time-bounded (CLAUDE.md NEVER #5).");
        }
    }
}
