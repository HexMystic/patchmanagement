using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// D-306, proven against the real fleet rather than argued.
///
/// <para>The lab publishes each container on <c>127.0.0.1:220x</c>, and the containers additionally
/// share one compose network on which they resolve each other by name. That is exactly the shape a
/// bastion chain needs: the first hop is reached over a real loopback socket, and every hop after it
/// is reachable ONLY from inside the network — through the hop before it. So a chain that quietly
/// stopped early could not reach the destination at all, which is what makes these assertions mean
/// something. NEVER #4 holds: every socket this opens is to <c>127.0.0.1</c>.</para>
///
/// <para><b>The assertion is the remote hostname, deliberately.</b> "It connected" is satisfied by a
/// chain truncated to its first hop — that was the pre-D-306 behaviour the refusal existed to prevent.
/// Asking the far end who it is, and comparing against the LAST element of the chain, is the only
/// assertion that separates "traversed the chain" from "connected to the jump host and reported
/// success".</para>
/// </summary>
[Collection(LabCollection.Name)]
public sealed class BastionChainFleetTests(LabFixture lab)
{
    /// <summary>Reached over loopback: the one host in a chain that needs a published port.</summary>
    private static LabHost Entry => LabFleet.All[0];       // ubuntu2204, 127.0.0.1:2201

    /// <summary>Reached from <see cref="Entry"/> by container name, on the lab network.</summary>
    private static LabHost Middle => LabFleet.All[2];      // debian12

    /// <summary>Reached from <see cref="Middle"/>. Deliberately a different OS family to the entry.</summary>
    private static LabHost Far => LabFleet.All[3];         // rocky9

    private const int InContainerSshPort = 22;

    private EndpointTarget ThroughTwoHops() => new()
    {
        TenantId = LabFixture.Tenant,
        Host = Far.Name,
        Port = InContainerSshPort,
        Protocol = EndpointProtocol.Ssh,
        Credential = LabFixture.LabCredential,
        BastionChain = new BastionChain(
        [
            new BastionHop("127.0.0.1", Entry.Port, LabFixture.LabCredential, LabFleet.Username),
            new BastionHop(Middle.Name, InContainerSshPort, LabFixture.LabCredential, LabFleet.Username),
        ]),
    };

    private static SshNetSessionFactory Factory() =>
        new(new ConnectorSecurityOptions { AllowUnknownHostKeys = true });

    [Fact]
    public async Task A_two_hop_chain_lands_on_the_far_host_rather_than_the_first_jump()
    {
        var plan = ConnectionPlanner.Plan(ThroughTwoHops());
        Assert.Equal(2, plan.Hops.Count);   // the plan under test comes from the real planner

        using var session = await Factory().ConnectAsync(
            plan, lab.Credentials.ResolveAsync, TimeSpan.FromSeconds(45), CancellationToken.None);

        var who = await session.RunAsync("hostname", TimeSpan.FromSeconds(30), default, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, who.Outcome);
        Assert.Equal(Far.Name, who.StandardOutput.Trim());

        // Named explicitly so a regression that truncates the chain fails with the reason rather than
        // an opaque hostname mismatch.
        Assert.NotEqual(Entry.Name, who.StandardOutput.Trim());
        Assert.NotEqual(Middle.Name, who.StandardOutput.Trim());
    }

    /// <summary>
    /// The far host is NOT published on loopback, so this is what proves the tunnel is load-bearing:
    /// if the chain were not carrying the connection, there would be no route to it at all.
    /// </summary>
    [Fact]
    public async Task The_far_host_of_the_chain_is_unreachable_without_the_tunnel()
    {
        var direct = new EndpointTarget
        {
            TenantId = LabFixture.Tenant,
            Host = Far.Name,
            Port = InContainerSshPort,
            Protocol = EndpointProtocol.Ssh,
            Credential = LabFixture.LabCredential,
        };

        var ex = await Assert.ThrowsAsync<ConnectorConnectException>(() => Factory().ConnectAsync(
            ConnectionPlanner.Plan(direct),
            lab.Credentials.ResolveAsync,
            TimeSpan.FromSeconds(20),
            CancellationToken.None));

        Assert.Equal(ConnectorOutcome.Unreachable, ex.Outcome);
    }

    /// <summary>
    /// A three-element chain, so "more than two" is exercised too — the old refusal was on
    /// <c>&gt; 1</c>, and a loop that happened to handle exactly two would satisfy the test above
    /// while still being a special case rather than a chain.
    /// </summary>
    [Fact]
    public async Task A_three_hop_chain_traverses_every_element()
    {
        var target = new EndpointTarget
        {
            TenantId = LabFixture.Tenant,
            Host = Far.Name,
            Port = InContainerSshPort,
            Protocol = EndpointProtocol.Ssh,
            Credential = LabFixture.LabCredential,
            BastionChain = new BastionChain(
            [
                new BastionHop("127.0.0.1", Entry.Port, LabFixture.LabCredential, LabFleet.Username),
                new BastionHop(Middle.Name, InContainerSshPort, LabFixture.LabCredential, LabFleet.Username),
                new BastionHop(LabFleet.All[1].Name, InContainerSshPort, LabFixture.LabCredential, LabFleet.Username),
            ]),
        };

        using var session = await Factory().ConnectAsync(
            ConnectionPlanner.Plan(target),
            lab.Credentials.ResolveAsync,
            TimeSpan.FromSeconds(60),
            CancellationToken.None);

        var who = await session.RunAsync("hostname", TimeSpan.FromSeconds(30), default, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, who.Outcome);
        Assert.Equal(Far.Name, who.StandardOutput.Trim());
    }

    /// <summary>
    /// Disposal has to unwind the whole chain, not just the last client. Every hop holds an
    /// authenticated transport and a listening local forward; leaking them per connection is a slow
    /// resource leak at the exact place the product is meant to scale (CLAUDE.md §2).
    /// </summary>
    [Fact]
    public async Task Disposing_a_chained_session_releases_every_hop_it_opened()
    {
        var plan = ConnectionPlanner.Plan(ThroughTwoHops());

        var session = await Factory().ConnectAsync(
            plan, lab.Credentials.ResolveAsync, TimeSpan.FromSeconds(45), CancellationToken.None);

        Assert.True(session.IsConnected);
        session.Dispose();
        Assert.False(session.IsConnected);

        // The far host is only reachable through the tunnel, so a second chain succeeding after the
        // first was torn down shows the teardown did not leave the fleet in a state that blocks reuse.
        using var again = await Factory().ConnectAsync(
            plan, lab.Credentials.ResolveAsync, TimeSpan.FromSeconds(45), CancellationToken.None);

        var who = await again.RunAsync("hostname", TimeSpan.FromSeconds(30), default, CancellationToken.None);
        Assert.Equal(Far.Name, who.StandardOutput.Trim());
    }
}
