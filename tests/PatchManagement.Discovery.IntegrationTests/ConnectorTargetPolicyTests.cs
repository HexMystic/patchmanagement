using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Connectors;
using PatchManagement.Connectors.DependencyInjection;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Discovery.DependencyInjection;
using PatchManagement.Persistence.Entities;
using PatchManagement.TestSupport.Credentials;
using Xunit;

namespace PatchManagement.Discovery.IntegrationTests;

/// <summary>
/// NEVER #4's in-product half, extended from the sweep to the <b>connector</b>.
///
/// <para><b>The hole D-306 opened.</b> Before bastion chains, an <see cref="EndpointTarget"/> named
/// one address and the connector dialled it directly, so "is this reachable from a dev machine" was
/// doing rough duty as a scope check. A chain removes that: the destination is reached from inside
/// the network by whichever jump host precedes it, so an out-of-lab address becomes reachable
/// <em>through</em> a lab container. Meanwhile <c>DiscoveryTargetPolicy</c> — the in-product guard
/// written for exactly this rule — was consumed only by <c>NetworkSweeper</c>, so no connector
/// target passed any check at all, and <c>.claude/hooks/lab_only_guard.py</c> structurally cannot
/// see a socket opened by our own C#.</para>
///
/// <para><b>The same allowlist, not a second one.</b> These targets are checked against
/// <c>Discovery:Security:AllowedTargets</c> — the list a sweep already honours. A parallel connector
/// allowlist would be a second declaration of one promise, and duplication that nothing checks
/// silently forks.</para>
///
/// <para>Every node is checked — each hop and the destination — before any socket is opened, so a
/// refused plan contacts nothing at all.</para>
/// </summary>
[Collection(DiscoveryPostgresCollection.Name)]
public sealed class ConnectorTargetPolicyTests(DiscoveryPostgresFixture fx)
{
    private static readonly CredentialRef LabCredential =
        new(Guid.Parse("1ab00000-0000-0000-0000-000000000001"));

    private const string LabHost = "127.0.0.1";
    private const int LabPort = 2201;

    /// <summary>An RFC1918 address the lab does not publish and a dev session must never contact.</summary>
    private const string OutOfLabHost = "10.99.0.1";

    /// <summary>A lab container by name — reachable on the compose network, NOT on loopback.</summary>
    private const string LabContainerName = "debian12";

    /// <summary>
    /// <b>The hole, stated as a test.</b> A chain whose destination is out of lab must be refused
    /// before anything is contacted — not attempted and then reported unreachable, which is what a
    /// missing guard looks like from the outside and is indistinguishable from "we tried".
    /// </summary>
    [Fact]
    public async Task A_chain_whose_destination_is_out_of_lab_is_refused_by_policy()
    {
        var target = new EndpointTarget
        {
            TenantId = await NewTenantAsync(),
            Host = OutOfLabHost,
            Port = 22,
            Protocol = EndpointProtocol.Ssh,
            Credential = LabCredential,
            BastionChain = new BastionChain(
            [
                new BastionHop(LabHost, LabPort, LabCredential, "labadmin"),
            ]),
        };

        var result = await ConnectAsync(target);

        Assert.Equal(ConnectorOutcome.ProtocolError, result.Outcome);
        Assert.Contains(OutOfLabHost, result.Detail ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("AllowedTargets", result.Detail ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// A hop out of scope is refused too. The destination is not the only address a chain contacts —
    /// checking it alone would leave the jump hosts themselves unguarded.
    /// </summary>
    [Fact]
    public async Task A_chain_whose_hop_is_out_of_lab_is_refused_by_policy()
    {
        var target = new EndpointTarget
        {
            TenantId = await NewTenantAsync(),
            Host = LabHost,
            Port = LabPort,
            Protocol = EndpointProtocol.Ssh,
            Credential = LabCredential,
            BastionChain = new BastionChain(
            [
                new BastionHop(OutOfLabHost, 22, LabCredential, "labadmin"),
            ]),
        };

        var result = await ConnectAsync(target);

        Assert.Equal(ConnectorOutcome.ProtocolError, result.Outcome);
        Assert.Contains(OutOfLabHost, result.Detail ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// A container reachable only on the compose network is out of scope for a dev session too. The
    /// legitimate dev path is <c>127.0.0.1:220x</c>, which is what the published ports are for —
    /// "it is a lab container" is not the test, "it is inside the declared scope" is.
    /// </summary>
    [Fact]
    public async Task A_lab_container_reached_by_name_rather_than_loopback_is_still_out_of_scope()
    {
        var target = new EndpointTarget
        {
            TenantId = await NewTenantAsync(),
            Host = LabContainerName,
            Port = 22,
            Protocol = EndpointProtocol.Ssh,
            Credential = LabCredential,
            BastionChain = new BastionChain(
            [
                new BastionHop(LabHost, LabPort, LabCredential, "labadmin"),
            ]),
        };

        var result = await ConnectAsync(target);

        Assert.Equal(ConnectorOutcome.ProtocolError, result.Outcome);
    }

    /// <summary>
    /// The control, and it is load-bearing: a guard that refused everything would pass every test
    /// above while making the product useless. An in-scope loopback target must still connect.
    /// </summary>
    [Fact]
    public async Task An_in_scope_loopback_target_still_connects()
    {
        var target = new EndpointTarget
        {
            TenantId = await NewTenantAsync(),
            Host = LabHost,
            Port = LabPort,
            Protocol = EndpointProtocol.Ssh,
            Credential = LabCredential,
        };

        Assert.Equal(ConnectorOutcome.Ok, (await ConnectAsync(target)).Outcome);
    }

    /// <summary>
    /// <c>localhost</c> must work as well as <c>127.0.0.1</c>. On Windows it resolves to <c>::1</c>
    /// first, and the allowlist is IPv4-only — so a policy that simply rejected what it could not
    /// express would refuse the fleet the dev lab actually publishes.
    /// </summary>
    [Fact]
    public async Task The_loopback_name_resolves_into_scope_rather_than_being_refused_as_unexpressible()
    {
        var target = new EndpointTarget
        {
            TenantId = await NewTenantAsync(),
            Host = "localhost",
            Port = LabPort,
            Protocol = EndpointProtocol.Ssh,
            Credential = LabCredential,
        };

        Assert.Equal(ConnectorOutcome.Ok, (await ConnectAsync(target)).Outcome);
    }

    private async Task<ConnectivityResult> ConnectAsync(EndpointTarget target)
    {
        var credentials = new FakeCredentialProvider();
        credentials.AddLabKey(LabCredential, "labadmin");

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Connectors:Security:AllowUnknownHostKeys"] = "true",
                // The dev scope, exactly as appsettings.Development.json declares it.
                ["Discovery:Security:AllowedTargets:0"] = "127.0.0.0/8",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ICredentialProvider>(credentials);
        services.AddScoped(_ => fx.AppContextFor(target.TenantId));
        services.AddConnectorsModule(configuration);
        services.AddDiscoveryModule(configuration);

        await using var provider = services.BuildServiceProvider(validateScopes: true);
        using var scope = provider.CreateScope();

        var connector = scope.ServiceProvider
            .GetRequiredService<IEndpointConnectorRegistry>()
            .For(EndpointProtocol.Ssh);

        return await connector.TestConnectivityAsync(target, CancellationToken.None);
    }

    private async Task<Guid> NewTenantAsync()
    {
        var id = Guid.NewGuid();
        await using var db = fx.OwnerContext();
        db.Tenants.Add(new Tenant
        {
            Id = id,
            Name = $"t-{id:N}",
            Status = "active",
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();
        return id;
    }
}
