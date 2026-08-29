using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// D-306, proven against the real fleet rather than argued.
///
/// <para>The lab publishes each container on <c>127.0.0.1:220x</c> and the containers additionally
/// share one compose network on which they resolve each other by name, so a chain's first hop is
/// reached over a real loopback socket and later hops by container name. NEVER #4 holds: every
/// socket this opens is to <c>127.0.0.1</c>.</para>
///
/// <para><b>The remote hostname is NOT sufficient to prove the chain was walked, and an earlier
/// version of this file wrongly assumed it was.</b> The lab network is flat — every container can
/// reach every other — so a chain truncated to its first hop still forwards to the destination and
/// still lands on the right host. A mutation replacing <c>plan.Hops</c> with <c>plan.Hops.Take(1)</c>
/// passed all four tests here. The claim that "a truncated chain physically cannot reach the far
/// host" was false; proving traversal needs something that is true only when every hop is
/// authenticated.</para>
///
/// <para><b>What replaced it: one distinct credential per hop.</b> Each hop and the destination
/// carry their own <see cref="CredentialRef"/> (all bound to the same lab key, so the fleet still
/// accepts them), and <see cref="RecordingCredentialProvider"/> counts resolutions per reference.
/// A hop that is never authenticated never resolves its reference, so truncation fails by name
/// instead of passing quietly. It also asserts each hop's key material was zeroed — multi-hop
/// credential hygiene that was previously inferred from the one-hop test.</para>
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

    /// <summary>A third jump, so "more than two" is exercised rather than a two-hop special case.</summary>
    private static LabHost Extra => LabFleet.All[1];       // ubuntu2404

    private const int InContainerSshPort = 22;

    // Distinct references, identical key. Distinctness is the whole mechanism: it is what makes
    // "this hop authenticated" observable without reaching inside the factory.
    private static readonly CredentialRef EntryCredential = new(Guid.Parse("b0570000-0000-0000-0000-000000000001"));
    private static readonly CredentialRef MiddleCredential = new(Guid.Parse("b0570000-0000-0000-0000-000000000002"));
    private static readonly CredentialRef ExtraCredential = new(Guid.Parse("b0570000-0000-0000-0000-000000000003"));
    private static readonly CredentialRef FarCredential = new(Guid.Parse("b0570000-0000-0000-0000-000000000004"));

    private RecordingCredentialProvider Recording()
    {
        foreach (var reference in new[] { EntryCredential, MiddleCredential, ExtraCredential, FarCredential })
            lab.Credentials.AddLabKey(reference, LabFleet.Username);

        return new RecordingCredentialProvider(lab.Credentials);
    }

    private static SshNetSessionFactory Factory() =>
        new(new ConnectorSecurityOptions { AllowUnknownHostKeys = true });

    private static BastionHop Hop(string host, int port, CredentialRef credential) =>
        new(host, port, credential, LabFleet.Username);

    private static EndpointTarget Target(BastionChain chain) => new()
    {
        TenantId = LabFixture.Tenant,
        Host = Far.Name,
        Port = InContainerSshPort,
        Protocol = EndpointProtocol.Ssh,
        Credential = FarCredential,
        BastionChain = chain,
    };

    private static EndpointTarget ThroughTwoHops() => Target(new BastionChain(
    [
        Hop("127.0.0.1", Entry.Port, EntryCredential),
        Hop(Middle.Name, InContainerSshPort, MiddleCredential),
    ]));

    [Fact]
    public async Task A_two_hop_chain_authenticates_at_every_hop_and_lands_on_the_far_host()
    {
        var recorder = Recording();
        var plan = ConnectionPlanner.Plan(ThroughTwoHops());
        Assert.Equal(2, plan.Hops.Count);   // the plan under test comes from the real planner

        using var session = await Factory().ConnectAsync(
            plan, recorder.ResolveAsync, hostKeys: null, TimeSpan.FromSeconds(45), CancellationToken.None);

        var who = await session.RunAsync("hostname", TimeSpan.FromSeconds(30), default, CancellationToken.None);
        Assert.Equal(ConnectorOutcome.Ok, who.Outcome);
        Assert.Equal(Far.Name, who.StandardOutput.Trim());

        // The assertion that actually detects a truncated chain. MIDDLE is the load-bearing one: the
        // lab network is flat, so dropping it still reaches Far and still reports the right hostname.
        Assert.Equal(1, recorder.CountFor(EntryCredential));
        Assert.Equal(1, recorder.CountFor(MiddleCredential));
        Assert.Equal(1, recorder.CountFor(FarCredential));

        // No hop may leave key material alive for the tunnel's lifetime — previously proven for one
        // hop only, which said nothing about the legs a chain adds.
        Assert.True(recorder.AllHandedOutBuffersAreZeroed, $"{recorder.UnzeroedBufferCount} buffers left unzeroed");
    }

    /// <summary>
    /// The far host is not published on loopback, so the tunnel is doing real work — but note this
    /// proves only that the destination is unreachable <b>from the test host</b>, not that every hop
    /// is required. The per-hop credential counts above are what prove traversal.
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
            hostKeys: null,
            TimeSpan.FromSeconds(20),
            CancellationToken.None));

        Assert.Equal(ConnectorOutcome.Unreachable, ex.Outcome);
    }

    /// <summary>
    /// Three hops, so a loop that happened to handle exactly two would not pass. The old refusal was
    /// on <c>&gt; 1</c>, which is precisely the boundary a two-hop-only implementation would clear.
    /// </summary>
    [Fact]
    public async Task A_three_hop_chain_authenticates_at_every_element()
    {
        var recorder = Recording();

        var target = Target(new BastionChain(
        [
            Hop("127.0.0.1", Entry.Port, EntryCredential),
            Hop(Middle.Name, InContainerSshPort, MiddleCredential),
            Hop(Extra.Name, InContainerSshPort, ExtraCredential),
        ]));

        using var session = await Factory().ConnectAsync(
            ConnectionPlanner.Plan(target), recorder.ResolveAsync, hostKeys: null,
            TimeSpan.FromSeconds(60), CancellationToken.None);

        var who = await session.RunAsync("hostname", TimeSpan.FromSeconds(30), default, CancellationToken.None);
        Assert.Equal(ConnectorOutcome.Ok, who.Outcome);
        Assert.Equal(Far.Name, who.StandardOutput.Trim());

        Assert.Equal(1, recorder.CountFor(EntryCredential));
        Assert.Equal(1, recorder.CountFor(MiddleCredential));
        Assert.Equal(1, recorder.CountFor(ExtraCredential));
        Assert.Equal(1, recorder.CountFor(FarCredential));
        Assert.True(recorder.AllHandedOutBuffersAreZeroed, $"{recorder.UnzeroedBufferCount} buffers left unzeroed");
    }

    /// <summary>
    /// Disposal has to unwind the whole chain, not just the last client. Every hop holds an
    /// authenticated transport and a listening local forward; leaking them per connection is a slow
    /// resource leak at the exact place the product is meant to scale (CLAUDE.md §2).
    /// </summary>
    [Fact]
    public async Task Disposing_a_chained_session_releases_every_hop_it_opened()
    {
        var recorder = Recording();
        var plan = ConnectionPlanner.Plan(ThroughTwoHops());

        var session = await Factory().ConnectAsync(
            plan, recorder.ResolveAsync, hostKeys: null, TimeSpan.FromSeconds(45), CancellationToken.None);

        Assert.True(session.IsConnected);
        session.Dispose();
        Assert.False(session.IsConnected);

        // A second chain over the same path must still authenticate every hop — a teardown that left
        // a forward or a jump-host client behind would show up as a leg that is no longer dialled.
        using var again = await Factory().ConnectAsync(
            plan, recorder.ResolveAsync, hostKeys: null, TimeSpan.FromSeconds(45), CancellationToken.None);

        var who = await again.RunAsync("hostname", TimeSpan.FromSeconds(30), default, CancellationToken.None);
        Assert.Equal(Far.Name, who.StandardOutput.Trim());

        Assert.Equal(2, recorder.CountFor(EntryCredential));
        Assert.Equal(2, recorder.CountFor(MiddleCredential));
        Assert.Equal(2, recorder.CountFor(FarCredential));
    }
}
