using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Discovery.Sweep;
using PatchManagement.Discovery.Tests.Fakes;

namespace PatchManagement.Discovery.Tests.Sweep;

/// <summary>
/// The in-product half of CLAUDE.md NEVER #4.
///
/// <para><c>.claude/hooks/lab_only_guard.py</c> reads Bash <c>ssh</c>/<c>scp</c>/<c>sftp</c> command
/// strings. It structurally cannot see a socket this process opens, and a sweep opens nothing but
/// sockets this process opens — so before these tests existed, the sweep was the one endpoint-
/// contacting feature in the product with no enforcement of NEVER #4 at all.</para>
///
/// <para><b>Every assertion here is on <see cref="FakePortProbe.Attempts"/>, not on the returned
/// host list.</b> "No hosts came back" is what a fully-executed sweep of an empty subnet looks
/// like too; only the absence of probe attempts distinguishes refusing to look from looking and
/// finding nothing.</para>
/// </summary>
public sealed class TargetPolicyTests
{
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");

    private static INetworkSweeper Sweeper(FakePortProbe probe, params string[] allowed) =>
        new NetworkSweeper(
            Options.Create(new DiscoverySweepOptions()),
            Options.Create(new DiscoverySecurityOptions { AllowedTargets = [.. allowed] }),
            probe,
            NullLogger<NetworkSweeper>.Instance);

    private static SweepRequest Request(params string[] ranges) =>
        new() { TenantId = Tenant, Ranges = ranges, Ports = [22] };

    /// <summary>
    /// The headline case. A routable RFC1918 address is not in the lab, so a dev session must not
    /// be able to reach it — and the refusal has to be an outcome the caller can see, not an empty
    /// result set.
    /// </summary>
    [Fact]
    public async Task A_range_outside_the_allowlist_is_refused()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe, "127.0.0.0/8");

        var result = await sweeper.SweepAsync(Request("10.0.0.0/30"), CancellationToken.None);

        Assert.Equal(SweepOutcome.RefusedByPolicy, result.Outcome);
        Assert.False(result.Succeeded);
        Assert.Contains(result.Refused, r => r.Range == "10.0.0.0/30");
    }

    /// <summary>
    /// The half that actually enforces anything. An outcome enum is a claim; an empty attempt log
    /// is the evidence. A guard that returned <c>RefusedByPolicy</c> after probing the range would
    /// satisfy the test above and none of NEVER #4.
    /// </summary>
    [Fact]
    public async Task A_refused_range_is_never_probed()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe, "127.0.0.0/8");

        var result = await sweeper.SweepAsync(Request("10.0.0.0/30"), CancellationToken.None);

        Assert.Empty(probe.Attempts);
        Assert.Equal(0, result.AddressesProbed);
    }

    /// <summary>
    /// Defaulted closed, the same way <c>ConnectorSecurityOptions.AllowUnknownHostKeys</c> is. A
    /// deployment that has not declared its scope sweeps nothing — including loopback.
    /// </summary>
    [Fact]
    public async Task An_empty_allowlist_permits_nothing()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe);

        var result = await sweeper.SweepAsync(Request("127.0.0.1/32"), CancellationToken.None);

        Assert.Equal(SweepOutcome.RefusedByPolicy, result.Outcome);
        Assert.Empty(probe.Attempts);
    }

    /// <summary>
    /// Refusal is all-or-nothing across the request. Sweeping the permitted ranges and quietly
    /// dropping the rest would report a coverage gap as a clean result — the exact dishonesty
    /// HARD-PROBLEMS #8 forbids, and the reason Phase 5's empty-batch-with-green-status defect was
    /// worth a rewrite.
    /// </summary>
    [Fact]
    public async Task One_disallowed_range_refuses_the_whole_sweep()
    {
        var probe = new FakePortProbe(("127.0.0.1", 22));
        var sweeper = Sweeper(probe, "127.0.0.0/8");

        var result = await sweeper.SweepAsync(
            Request("127.0.0.1/32", "192.168.1.0/30"), CancellationToken.None);

        Assert.Equal(SweepOutcome.RefusedByPolicy, result.Outcome);
        Assert.Empty(probe.Attempts);
        Assert.Contains(result.Refused, r => r.Range == "192.168.1.0/30");
        Assert.DoesNotContain(result.Refused, r => r.Range == "127.0.0.1/32");
    }

    /// <summary>
    /// A range that only partly overlaps an allowed block is refused, not clipped. An operator who
    /// asked for a /16 and silently received one /24 of it has been told what a fraction of their
    /// estate contains, with no way to tell that from the whole answer.
    /// </summary>
    [Fact]
    public async Task A_partially_overlapping_range_is_refused_rather_than_clipped()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe, "192.168.1.0/24");

        var result = await sweeper.SweepAsync(Request("192.168.0.0/16"), CancellationToken.None);

        Assert.Equal(SweepOutcome.RefusedByPolicy, result.Outcome);
        Assert.Empty(probe.Attempts);
    }

    /// <summary>The lab case: loopback is permitted once declared, and is actually probed.</summary>
    [Fact]
    public async Task An_allowed_range_is_swept()
    {
        var probe = new FakePortProbe(("127.0.0.1", 22));
        var sweeper = Sweeper(probe, "127.0.0.0/8");

        var result = await sweeper.SweepAsync(Request("127.0.0.1/32"), CancellationToken.None);

        Assert.Equal(SweepOutcome.Ok, result.Outcome);
        Assert.NotEmpty(probe.Attempts);
        var host = Assert.Single(result.Hosts);
        Assert.Equal("127.0.0.1", host.Address);
        Assert.Equal([22], host.OpenPorts);
    }

    /// <summary>
    /// A bare address in the allowlist means that single host, not its subnet. Otherwise an
    /// operator declaring one jump box would silently authorise its whole /24.
    /// </summary>
    [Fact]
    public async Task A_bare_address_in_the_allowlist_authorises_only_that_host()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe, "127.0.0.1");

        var neighbour = await sweeper.SweepAsync(Request("127.0.0.2/32"), CancellationToken.None);

        Assert.Equal(SweepOutcome.RefusedByPolicy, neighbour.Outcome);
        Assert.Empty(probe.Attempts);
    }

    /// <summary>
    /// A malformed allowlist entry must not silently widen the policy. It is dropped, and a request
    /// that only that entry would have permitted is still refused — fail closed, never open.
    /// </summary>
    [Fact]
    public async Task A_malformed_allowlist_entry_does_not_open_the_gate()
    {
        var probe = new FakePortProbe();
        var sweeper = Sweeper(probe, "not-a-cidr", "999.1.1.1/24");

        var result = await sweeper.SweepAsync(Request("127.0.0.1/32"), CancellationToken.None);

        Assert.Equal(SweepOutcome.RefusedByPolicy, result.Outcome);
        Assert.Empty(probe.Attempts);
    }

    /// <summary>
    /// Policy is evaluated before the sweep touches anything, so an allowed request stays allowed
    /// no matter how many times it is repeated — the sweep is a pure read (NEVER #5 idempotency).
    /// </summary>
    [Fact]
    public async Task Repeating_an_allowed_sweep_observes_the_same_hosts()
    {
        var probe = new FakePortProbe(("127.0.0.1", 22));
        var sweeper = Sweeper(probe, "127.0.0.0/8");

        var first = await sweeper.SweepAsync(Request("127.0.0.1/32"), CancellationToken.None);
        var second = await sweeper.SweepAsync(Request("127.0.0.1/32"), CancellationToken.None);

        Assert.Equal(first.Outcome, second.Outcome);
        Assert.Equal(
            first.Hosts.Select(h => h.Address),
            second.Hosts.Select(h => h.Address));
    }
}
