using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests.Bastion;

/// <summary>
/// Exit criterion (f): the bastion path is exercised in a unit test with no cloud assumption in the
/// connector. ADR 0003 — direct versus jump-host is a property of the target configuration, never a
/// branch in connector code.
///
/// <para>Planning is a pure function of the target, so all of this runs without a socket.</para>
/// </summary>
public sealed class BastionPlanningTests
{
    private static readonly Guid Tenant = Guid.Parse("eeeeeeee-0000-0000-0000-000000000005");
    private static readonly CredentialRef TargetCredential = new(Guid.Parse("11110000-0000-0000-0000-000000000001"));
    private static readonly CredentialRef BastionCredential = new(Guid.Parse("22220000-0000-0000-0000-000000000002"));

    private static EndpointTarget Direct() => new()
    {
        TenantId = Tenant,
        Host = "10.0.0.5",
        Port = 22,
        Protocol = EndpointProtocol.Ssh,
        Credential = TargetCredential,
    };

    private static EndpointTarget ViaBastion() => Direct() with
    {
        Bastion = new BastionHop("jump.example.net", 2222, BastionCredential, "jumpuser"),
    };

    [Fact]
    public void A_target_with_no_bastion_plans_a_direct_connection()
    {
        var plan = ConnectionPlanner.Plan(Direct());

        Assert.True(plan.IsDirect);
        Assert.Empty(plan.Hops);
        Assert.Equal("10.0.0.5", plan.Destination.Host);
        Assert.Equal(22, plan.Destination.Port);
    }

    [Fact]
    public void A_target_with_a_bastion_plans_one_hop_then_the_destination()
    {
        var plan = ConnectionPlanner.Plan(ViaBastion());

        Assert.False(plan.IsDirect);

        var hop = Assert.Single(plan.Hops);
        Assert.Equal("jump.example.net", hop.Host);
        Assert.Equal(2222, hop.Port);
        Assert.Equal(BastionCredential.Id, hop.Credential.Id);
        Assert.Equal("jumpuser", hop.Username);

        // Order matters: hops are traversed before the destination is reached.
        Assert.Equal("10.0.0.5", plan.Destination.Host);
    }

    [Fact]
    public void Choosing_direct_or_tunnelled_is_data_not_a_branch_on_where_the_target_lives()
    {
        // The SAME code path produces both plans; only the target's configuration differs. This is
        // ADR 0003 stated as a test: nothing about the plan depends on knowing that jump.example.net
        // is a cloud bastion, an on-prem jump box or a laptop under someone's desk.
        var direct = ConnectionPlanner.Plan(Direct());
        var tunnelled = ConnectionPlanner.Plan(ViaBastion());

        Assert.True(direct.IsDirect);
        Assert.False(tunnelled.IsDirect);
        Assert.Equal(direct.Destination.Host, tunnelled.Destination.Host);
    }

    [Fact]
    public async Task The_bastion_credential_is_resolved_separately_from_the_target_credential()
    {
        var credentials = new FakeCredentialProvider();
        credentials.Add(TargetCredential, "target-key"u8.ToArray(), CredentialKind.SshKey, "labadmin");
        credentials.Add(BastionCredential, "bastion-key"u8.ToArray(), CredentialKind.SshKey, "jumpuser");
        var recorder = new RecordingCredentialProvider(credentials);

        var factory = new StubSshSessionFactory(() => new RecordingSshSession());
        await factory.ConnectAsync(
            ConnectionPlanner.Plan(ViaBastion()), recorder.ResolveAsync, hostKeys: null,
            TimeSpan.FromSeconds(5), CancellationToken.None);

        // Two distinct references, resolved independently. Reusing the target's credential to reach
        // the jump host would be a silent authorization change — and would fail confusingly on any
        // estate where the bastion has its own account, which is the normal arrangement.
        Assert.Equal(1, recorder.CountFor(BastionCredential));
        Assert.Equal(1, recorder.CountFor(TargetCredential));

        // Both released: a bastion hop must not leave key material alive for the tunnel's lifetime.
        Assert.True(recorder.AllHandedOutBuffersAreZeroed);
    }

    /// <summary>
    /// <b>Replaces</b> <c>A_multi_hop_chain_is_rejected_by_name_rather_than_silently_truncated</c>
    /// (D-306, closed slice 5). That test hand-built a two-hop <see cref="ConnectionPlan"/> because
    /// no target could produce one, and asserted the factory refused it.
    ///
    /// <para>The property it protected — a chain is never silently truncated to its first hop — is
    /// what survives, and it is now proven the other way round: every hop is traversed. Planning is
    /// asserted here; that the connection actually lands on the LAST host, reachable only through the
    /// ones before it, is asserted against the real fleet in <c>BastionChainFleetTests</c>, because a
    /// unit test cannot tell a traversed chain from a truncated one.</para>
    /// </summary>
    [Fact]
    public void A_multi_hop_chain_is_planned_in_full_rather_than_truncated_to_its_first_hop()
    {
        var plan = ConnectionPlanner.Plan(Direct() with
        {
            BastionChain = new BastionChain(
            [
                new BastionHop("jump-a", 22, BastionCredential, "jumpuser"),
                new BastionHop("jump-b", 22, BastionCredential, "jumpuser"),
            ]),
        });

        Assert.Equal(["jump-a", "jump-b"], plan.Hops.Select(h => h.Host));
        Assert.Equal("10.0.0.5", plan.Destination.Host);
    }
}
