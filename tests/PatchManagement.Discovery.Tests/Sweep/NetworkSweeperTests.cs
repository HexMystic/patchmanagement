using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Discovery.Sweep;
using PatchManagement.Discovery.Tests.Fakes;

namespace PatchManagement.Discovery.Tests.Sweep;

/// <summary>
/// Sweep behaviour that is not about the target policy: tenant scoping, bounded ranges, honest
/// refusal of what cannot be enumerated, and the port set actually probed.
/// </summary>
public sealed class NetworkSweeperTests
{
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");

    private static INetworkSweeper Sweeper(
        FakePortProbe probe, DiscoverySweepOptions? options = null, params string[] allowed) =>
        new NetworkSweeper(
            Options.Create(options ?? new DiscoverySweepOptions()),
            Options.Create(new DiscoverySecurityOptions
            {
                AllowedTargets = allowed.Length > 0 ? [.. allowed] : ["127.0.0.0/8"],
            }),
            probe,
            NullLogger<NetworkSweeper>.Instance);

    /// <summary>
    /// Discovery results are tenant-scoped data (CLAUDE.md 4.1). A sweep with no tenant has nobody
    /// to attribute its findings to, so it is a caller bug rather than an outcome — and defaulting
    /// the tenant would be how cross-tenant data gets written.
    /// </summary>
    [Fact]
    public async Task A_sweep_without_a_tenant_is_refused()
    {
        var sweeper = Sweeper(new FakePortProbe());

        await Assert.ThrowsAsync<ArgumentException>(() => sweeper.SweepAsync(
            new SweepRequest { TenantId = Guid.Empty, Ranges = ["127.0.0.1/32"] },
            CancellationToken.None));
    }

    /// <summary>
    /// IPv6 is refused BY NAME, not skipped. A /64 holds 1.8e19 addresses, so there is no bound
    /// under which enumerating one is meaningful; accepting the syntax and probing a prefix would
    /// describe the estate from an arbitrary sliver of it.
    /// </summary>
    [Fact]
    public async Task An_ipv6_range_is_refused_by_name()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe);

        var result = await sweeper.SweepAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["2001:db8::/64"] },
            CancellationToken.None);

        Assert.Equal(SweepOutcome.InvalidRange, result.Outcome);
        var refused = Assert.Single(result.Refused);
        Assert.Equal("2001:db8::/64", refused.Range);
        Assert.Contains("IPv6", refused.Reason, StringComparison.Ordinal);
        Assert.Empty(probe.Attempts);
    }

    /// <summary>
    /// A range above the configured host cap is refused rather than truncated — NEVER #5 applied to
    /// the one operation whose cost an operator sets by typing a prefix length.
    /// </summary>
    [Fact]
    public async Task A_range_above_the_host_cap_is_refused_rather_than_truncated()
    {
        var probe = new FakePortProbe();
        var options = new DiscoverySweepOptions { MaxHostsPerRange = 16 };
        var sweeper = Sweeper(probe, options, "10.0.0.0/8");

        var result = await sweeper.SweepAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["10.0.0.0/24"] },
            CancellationToken.None);

        Assert.Equal(SweepOutcome.InvalidRange, result.Outcome);
        Assert.Empty(probe.Attempts);
        Assert.Contains("cap", Assert.Single(result.Refused).Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_malformed_range_is_refused_by_name()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe);

        var result = await sweeper.SweepAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["not-a-range"] },
            CancellationToken.None);

        Assert.Equal(SweepOutcome.InvalidRange, result.Outcome);
        Assert.Equal("not-a-range", Assert.Single(result.Refused).Range);
        Assert.Empty(probe.Attempts);
    }

    /// <summary>
    /// Every address in the block is probed, including the network and broadcast addresses. A
    /// discovery tool with a built-in blind spot would undercut the feature it belongs to.
    /// </summary>
    [Fact]
    public async Task Every_address_in_the_block_is_probed_including_network_and_broadcast()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe);

        var result = await sweeper.SweepAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["127.0.0.0/30"], Ports = [22] },
            CancellationToken.None);

        Assert.Equal(SweepOutcome.Ok, result.Outcome);
        Assert.Equal(4, result.AddressesProbed);
        Assert.Equal(
            new[] { "127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3" },
            probe.AddressesAttempted.Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// The default port set is the management protocols this product speaks (CLAUDE.md 2), not a
    /// general port scan — discovery looks for endpoints it could manage.
    /// </summary>
    [Fact]
    public async Task The_default_port_set_is_the_management_ports()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe);

        await sweeper.SweepAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["127.0.0.1/32"] },
            CancellationToken.None);

        Assert.Equal(
            new[] { 22, 445, 5985, 5986 },
            probe.Attempts.Select(a => a.Port).Order());
    }

    /// <summary>A host answering on several ports is reported once, with the ports collected.</summary>
    [Fact]
    public async Task A_host_answering_on_several_ports_is_reported_once()
    {
        var probe = new FakePortProbe(("127.0.0.1", 22), ("127.0.0.1", 445));
        var sweeper = Sweeper(probe);

        var result = await sweeper.SweepAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["127.0.0.1/32"] },
            CancellationToken.None);

        var host = Assert.Single(result.Hosts);
        Assert.Equal([22, 445], host.OpenPorts);
    }

    /// <summary>
    /// A sweep that finds nothing is <see cref="SweepOutcome.Ok"/> with an empty host list and a
    /// non-zero probe count. That combination is what makes it distinguishable from a refusal,
    /// which reports zero probed.
    /// </summary>
    [Fact]
    public async Task A_sweep_that_finds_nothing_is_still_a_successful_sweep()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe);

        var result = await sweeper.SweepAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["127.0.0.0/30"], Ports = [22] },
            CancellationToken.None);

        Assert.Equal(SweepOutcome.Ok, result.Outcome);
        Assert.True(result.Succeeded);
        Assert.Empty(result.Hosts);
        Assert.Equal(4, result.AddressesProbed);
    }

    /// <summary>A cancelled sweep stops rather than draining every remaining probe (NEVER #5).</summary>
    [Fact]
    public async Task A_cancelled_sweep_is_abandoned()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sweeper.SweepAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["127.0.0.0/24"], Ports = [22] },
            cts.Token));
    }
}
