using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Discovery.Sweep;

namespace PatchManagement.Discovery.IntegrationTests;

/// <summary>
/// Phase 4 criterion (a), against the real fleet: the sweep finds the lab containers on loopback
/// and the open ports it reports match what <c>lab/docker-compose.yml</c> actually publishes.
///
/// <para><b>What this proves that the unit suite cannot.</b> Every target-policy and sweep test in
/// <c>PatchManagement.Discovery.Tests</c> runs against a fake probe, deliberately — a suite that
/// reached the network to prove the network guard works would be doing the thing the guard forbids.
/// The consequence is that <see cref="TcpPortProbe"/>, the one component that actually opens a
/// socket, had never touched a real TCP stack. This suite is where that changes.</para>
///
/// <para><b>Five containers, one address.</b> The lab publishes all five distros on
/// <c>127.0.0.1</c> at different host ports, so "the sweep finds the five containers" is observed
/// here as one host answering on five ports, not as five hosts. Establishing that those five
/// endpoints are five distinct machines needs a login, which is inventory's job (slice 3) — this
/// suite does not claim it.</para>
///
/// <para><b>NEVER #4.</b> Every address touched here is loopback, and the policy is configured to
/// permit loopback only. <c>A_non_lab_range_is_still_refused_with_the_real_probe</c> is the one
/// test that names a non-lab range, and it exists to prove nothing is contacted.</para>
/// </summary>
public sealed class LabSweepTests
{
    private static readonly Guid Tenant = Guid.Parse("7e9a0000-0000-0000-0000-000000000001");

    private static INetworkSweeper Sweeper() =>
        new NetworkSweeper(
            Options.Create(new DiscoverySweepOptions()),
            Options.Create(new DiscoverySecurityOptions { AllowedTargets = ["127.0.0.0/8"] }),
            new TcpPortProbe(),
            NullLogger<NetworkSweeper>.Instance);

    /// <summary>
    /// Criterion (a). Sweeps <c>127.0.0.1/32</c> across the fleet's published ports and requires
    /// every one of them to answer.
    ///
    /// <para>The expected set is read from the compose file, so this fails if a port is renumbered
    /// there and the fleet is not restarted — which is the honest outcome, not a false alarm.</para>
    /// </summary>
    [Fact]
    public async Task The_sweep_finds_every_published_lab_port_on_loopback()
    {
        var expected = LabPublishedPorts.All;
        await RequireFleetUpAsync(expected);

        var result = await Sweeper().ScanAsync(
            new SweepRequest
            {
                TenantId = Tenant,
                Ranges = ["127.0.0.1/32"],
                Ports = expected,
            },
            CancellationToken.None);

        Assert.Equal(SweepOutcome.Ok, result.Outcome);
        Assert.Equal(1, result.AddressesProbed);

        var host = Assert.Single(result.Hosts);
        Assert.Equal("127.0.0.1", host.Address);

        // Equality, not containment: a subset check would pass while the sweep silently missed a
        // container, which is precisely the coverage gap this phase exists to surface.
        Assert.Equal(expected, host.OpenPorts);
    }

    /// <summary>
    /// The control that makes the test above mean something. A probe that reported every port open
    /// would satisfy an "all five answered" assertion perfectly — so a port that nothing is
    /// listening on must come back closed, and the host must then not be reported at all.
    ///
    /// <para>The port is obtained by binding an ephemeral listener and closing it, rather than
    /// guessing a number nobody uses. Guessing is how this kind of control test quietly becomes a
    /// test of someone else's service.</para>
    /// </summary>
    [Fact]
    public async Task A_port_nothing_listens_on_is_reported_closed()
    {
        var closedPort = ReserveThenReleasePort();

        var result = await Sweeper().ScanAsync(
            new SweepRequest
            {
                TenantId = Tenant,
                Ranges = ["127.0.0.1/32"],
                Ports = [closedPort],
            },
            CancellationToken.None);

        Assert.Equal(SweepOutcome.Ok, result.Outcome);
        Assert.Equal(1, result.AddressesProbed);
        Assert.Empty(result.Hosts);
    }

    /// <summary>
    /// The real probe distinguishes a bound port from a closed one on the same address, in one
    /// test, so neither half can be explained by an environment quirk.
    /// </summary>
    [Fact]
    public async Task The_real_probe_separates_a_bound_port_from_a_closed_one()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var boundPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var probe = new TcpPortProbe();
            var budget = TimeSpan.FromSeconds(2);

            var open = await probe.ProbeAsync("127.0.0.1", boundPort, budget, CancellationToken.None);
            Assert.True(open.Open, $"127.0.0.1:{boundPort} has a listener bound but was reported closed.");
            Assert.True(open.Elapsed > TimeSpan.Zero);

            listener.Stop();

            var closed = await probe.ProbeAsync("127.0.0.1", boundPort, budget, CancellationToken.None);
            Assert.False(closed.Open, $"127.0.0.1:{boundPort} has no listener but was reported open.");
        }
        finally
        {
            listener.Dispose();
        }
    }

    /// <summary>
    /// NEVER #4 under real conditions. Every policy proof in the unit suite substitutes the probe;
    /// this one keeps the real <see cref="TcpPortProbe"/> wired in and requires the refusal to
    /// happen anyway — <c>AddressesProbed == 0</c> is the observable that says no socket was opened.
    /// </summary>
    [Fact]
    public async Task A_non_lab_range_is_still_refused_with_the_real_probe()
    {
        var result = await Sweeper().ScanAsync(
            new SweepRequest { TenantId = Tenant, Ranges = ["10.0.0.0/30"], Ports = [22] },
            CancellationToken.None);

        Assert.Equal(SweepOutcome.RefusedByPolicy, result.Outcome);
        Assert.Equal(0, result.AddressesProbed);
        Assert.Empty(result.Hosts);
    }

    /// <summary>
    /// Sweeping twice observes the same fleet — criterion (h) for the sweep specifically. It is a
    /// pure read, so this is cheap to hold and worth pinning before slice 2 gives it a database to
    /// write to.
    /// </summary>
    [Fact]
    public async Task Sweeping_the_lab_twice_observes_the_same_fleet()
    {
        var expected = LabPublishedPorts.All;
        await RequireFleetUpAsync(expected);

        var sweeper = Sweeper();
        var request = new SweepRequest
        {
            TenantId = Tenant,
            Ranges = ["127.0.0.1/32"],
            Ports = expected,
        };

        var first = await sweeper.ScanAsync(request, CancellationToken.None);
        var second = await sweeper.ScanAsync(request, CancellationToken.None);

        Assert.Equal(first.Outcome, second.Outcome);
        Assert.Equal(
            first.Hosts.Select(h => (h.Address, Ports: string.Join(",", h.OpenPorts))),
            second.Hosts.Select(h => (h.Address, Ports: string.Join(",", h.OpenPorts))));
    }

    /// <summary>
    /// Fails with the command that fixes it, rather than letting the sweep test report "the lab has
    /// no open ports" — which reads as a product defect when it is a stopped container.
    /// </summary>
    private static async Task RequireFleetUpAsync(IReadOnlyList<int> ports)
    {
        var down = new List<int>();

        foreach (var port in ports)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await socket.ConnectAsync(IPAddress.Loopback, port, deadline.Token);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                down.Add(port);
            }
        }

        if (down.Count > 0)
        {
            throw new InvalidOperationException(
                $"The lab fleet is not fully up — nothing is listening on 127.0.0.1:"
                + $"{string.Join(", 127.0.0.1:", down)}.{Environment.NewLine}"
                + "Bring it up FROM THE MAIN WORKTREE (WORKFLOW.md §3 — only it runs Docker infra):"
                + Environment.NewLine
                + "  docker compose -f lab/docker-compose.yml up -d");
        }
    }

    /// <summary>An ephemeral port that was bound a moment ago and is now free.</summary>
    private static int ReserveThenReleasePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        listener.Dispose();
        return port;
    }
}
