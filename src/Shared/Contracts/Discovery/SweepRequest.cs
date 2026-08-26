namespace PatchManagement.Contracts.Discovery;

/// <summary>
/// A request to sweep one or more IPv4 CIDR ranges for reachable hosts and open management ports.
///
/// <para><see cref="TenantId"/> is required and is not decoration: discovery results are
/// tenant-scoped data (CLAUDE.md §4.1), and the ranges an operator may sweep are a tenant's
/// property. A sweep with no tenant has no one to attribute its findings to, so it is refused
/// rather than defaulted.</para>
/// </summary>
public sealed record SweepRequest
{
    public required Guid TenantId { get; init; }

    /// <summary>IPv4 CIDR blocks to sweep, e.g. <c>127.0.0.1/32</c>. Never empty.</summary>
    public required IReadOnlyList<string> Ranges { get; init; }

    /// <summary>
    /// Ports to probe on each address. Null uses the configured management-port set
    /// (22 / 5985 / 5986 / 445 by default).
    /// </summary>
    public IReadOnlyList<int>? Ports { get; init; }
}
