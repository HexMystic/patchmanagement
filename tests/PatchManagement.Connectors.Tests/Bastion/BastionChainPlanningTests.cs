using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Contracts.States;

namespace PatchManagement.Connectors.Tests.Bastion;

/// <summary>
/// D-306. <see cref="EndpointTarget.Bastion"/> is a single hop, so <see cref="ConnectionPlanner.Plan"/>
/// could only ever emit 0 or 1 — which made the factory's "more than one hop" refusal unreachable from
/// any real target and testable only by hand-building a <see cref="ConnectionPlan"/>. A refusal nothing
/// can trigger is not a safeguard, it is dead code that reads like one.
///
/// <para><see cref="BastionChain"/> is the topology model that makes the multi-hop case expressible
/// (approved additively 2026-08-27 under ADR 0017 — <c>Bastion</c> stays as the one-hop shorthand).
/// These tests drive the REAL planner: every plan below is what a configured target actually produces.</para>
/// </summary>
public sealed class BastionChainPlanningTests
{
    private static readonly Guid Tenant = Guid.Parse("eeeeeeee-0000-0000-0000-000000000006");
    private static readonly CredentialRef TargetCredential = new(Guid.Parse("11110000-0000-0000-0000-000000000001"));
    private static readonly CredentialRef FirstHop = new(Guid.Parse("22220000-0000-0000-0000-000000000002"));
    private static readonly CredentialRef SecondHop = new(Guid.Parse("33330000-0000-0000-0000-000000000003"));

    private static EndpointTarget Direct() => new()
    {
        TenantId = Tenant,
        Host = "10.0.0.5",
        Port = 22,
        Protocol = EndpointProtocol.Ssh,
        Credential = TargetCredential,
    };

    [Fact]
    public void The_planner_emits_every_hop_of_a_chain_in_configured_order()
    {
        var target = Direct() with
        {
            BastionChain = new BastionChain(
            [
                new BastionHop("jump-a", 2222, FirstHop, "user-a"),
                new BastionHop("jump-b", 2223, SecondHop, "user-b"),
            ]),
        };

        var plan = ConnectionPlanner.Plan(target);

        Assert.False(plan.IsDirect);
        Assert.Equal(2, plan.Hops.Count);

        // Order is the whole contract: hop[0] is the machine a socket is opened to, and each later
        // hop is reached THROUGH the one before it. A plan that reordered them would tunnel through
        // a host the operator never authorised.
        Assert.Equal("jump-a", plan.Hops[0].Host);
        Assert.Equal(2222, plan.Hops[0].Port);
        Assert.Equal(FirstHop.Id, plan.Hops[0].Credential.Id);
        Assert.Equal("user-a", plan.Hops[0].Username);

        Assert.Equal("jump-b", plan.Hops[1].Host);
        Assert.Equal(2223, plan.Hops[1].Port);
        Assert.Equal(SecondHop.Id, plan.Hops[1].Credential.Id);
        Assert.Equal("user-b", plan.Hops[1].Username);

        Assert.Equal("10.0.0.5", plan.Destination.Host);
    }

    [Fact]
    public void A_single_element_chain_plans_exactly_what_the_one_hop_shorthand_plans()
    {
        // The additive shape has to be a true superset, or the two spellings drift and a chain of one
        // becomes subtly different from the Bastion property it is meant to generalise.
        var shorthand = ConnectionPlanner.Plan(Direct() with
        {
            Bastion = new BastionHop("jump-a", 2222, FirstHop, "user-a"),
        });

        var chained = ConnectionPlanner.Plan(Direct() with
        {
            BastionChain = new BastionChain([new BastionHop("jump-a", 2222, FirstHop, "user-a")]),
        });

        // Compared field by field rather than with Assert.Equal(shorthand, chained). ConnectionPlan is
        // a record, but its Hops is an IReadOnlyList, so the compiler-generated equality compares that
        // list BY REFERENCE — two structurally identical plans are never Equal. Asserting the content
        // is both what this test means and immune to that trap.
        Assert.Equal(shorthand.TenantId, chained.TenantId);
        Assert.Equal(shorthand.Destination, chained.Destination);
        Assert.Equal(shorthand.IsDirect, chained.IsDirect);
        Assert.Equal(shorthand.Hops, chained.Hops);
    }

    [Fact]
    public void A_chain_hop_with_no_port_falls_back_to_the_ssh_default_like_the_shorthand_does()
    {
        var plan = ConnectionPlanner.Plan(Direct() with
        {
            BastionChain = new BastionChain([new BastionHop("jump-a", 0, FirstHop, "user-a")]),
        });

        Assert.Equal(22, Assert.Single(plan.Hops).Port);
    }

    /// <summary>
    /// The refusal that replaces the old hand-built one, and unlike it this one is REACHABLE: it is
    /// produced by the real planner from a target an operator can actually configure.
    /// </summary>
    [Fact]
    public void Configuring_both_the_shorthand_and_a_chain_is_refused_by_name_rather_than_one_silently_winning()
    {
        var target = Direct() with
        {
            Bastion = new BastionHop("jump-a", 2222, FirstHop, "user-a"),
            BastionChain = new BastionChain([new BastionHop("jump-b", 2223, SecondHop, "user-b")]),
        };

        var ex = Assert.Throws<ArgumentException>(() => ConnectionPlanner.Plan(target));

        // Either could plausibly be "the" topology, so picking one would tunnel through a host the
        // operator did not choose and report success — the same failure the multi-hop refusal exists
        // to prevent, one level up.
        Assert.Contains("Bastion", ex.Message, StringComparison.Ordinal);
        Assert.Contains("BastionChain", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_chain_is_refused_at_construction_rather_than_planning_a_direct_connection()
    {
        // Silently planning direct would take a target the operator deliberately placed behind a
        // bastion and connect to it straight, which on a segmented network either fails confusingly
        // or — worse — succeeds via a path that was supposed to be closed.
        Assert.Throws<ArgumentException>(() => new BastionChain([]));
    }

    /// <summary>
    /// The refusal must reach a caller as a <b>typed result</b>, not as an exception thrown out of
    /// <see cref="IEndpointConnector"/>.
    ///
    /// <para>CLAUDE.md §5: endpoint operations model failure in their return value rather than
    /// throwing. It matters more than tidiness here — a sweep walking 10,000 targets must not be
    /// taken down by one row of bad topology configuration, and <c>scan-failed</c> is the honest
    /// answer for a target we could not even plan a route to. What must NOT happen is the failure
    /// being reported as <c>Unreachable</c>, which would send someone to the network team over a
    /// configuration mistake (HARD-PROBLEMS #12).</para>
    /// </summary>
    [Fact]
    public async Task An_ambiguous_topology_returns_a_typed_failure_rather_than_throwing_out_of_the_connector()
    {
        var harness = ConnectorHarness.Build();

        var target = ConnectorHarness.Target() with
        {
            Bastion = new BastionHop("jump-a", 2222, FirstHop, "user-a"),
            BastionChain = new BastionChain([new BastionHop("jump-b", 2223, SecondHop, "user-b")]),
        };

        var result = await harness.Connector.RunAsync(
            target, new RemoteCommand { CommandLine = "true" }, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.ProtocolError, result.Outcome);
        Assert.Equal(EndpointState.ScanFailed, result.Outcome.ToEndpointState());
        Assert.Contains("BastionChain", result.Detail ?? string.Empty, StringComparison.Ordinal);
    }
}
