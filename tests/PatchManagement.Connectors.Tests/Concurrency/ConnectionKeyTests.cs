using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Tests.Concurrency;

/// <summary>
/// The pool key decides what may share an authenticated transport, so every field it omits is a
/// silent sharing rule.
/// </summary>
public sealed class ConnectionKeyTests
{
    private static readonly Guid TenantA = Guid.Parse("aaaaaaaa-1111-1111-1111-111111111111");
    private static readonly Guid TenantB = Guid.Parse("bbbbbbbb-2222-2222-2222-222222222222");
    private static readonly CredentialRef Credential = new(Guid.Parse("cccccccc-3333-3333-3333-333333333333"));

    private static EndpointTarget Target(Guid tenant) => new()
    {
        TenantId = tenant,
        Host = "localhost",
        Port = 2201,
        Protocol = EndpointProtocol.Ssh,
        Credential = Credential,
    };

    [Fact]
    public void Two_tenants_on_the_same_host_with_the_same_credential_get_different_keys()
    {
        var a = ConnectionKey.For(ConnectionPlanner.Plan(Target(TenantA)));
        var b = ConnectionKey.For(ConnectionPlanner.Plan(Target(TenantB)));

        // Before tenant was in the key these were identical, and isolation survived only because
        // credential ids happen to differ per tenant — a property of the data, not of the code.
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void The_same_tenant_and_target_produce_a_stable_key()
    {
        var first = ConnectionKey.For(ConnectionPlanner.Plan(Target(TenantA)));
        var second = ConnectionKey.For(ConnectionPlanner.Plan(Target(TenantA)));

        // The control: if the key were unstable nothing would ever be reused and the pool would be
        // pointless, which would make the test above pass for entirely the wrong reason.
        Assert.Equal(first, second);
    }

    [Fact]
    public void Bastion_hops_differing_only_by_username_do_not_collide()
    {
        var baseTarget = Target(TenantA);
        var viaAlice = baseTarget with
        {
            Bastion = new BastionHop("jump", 22, Credential, "alice"),
        };
        var viaBob = baseTarget with
        {
            Bastion = new BastionHop("jump", 22, Credential, "bob"),
        };

        // Logging in as a different user is a different session by any reasonable definition; the
        // key previously dropped the username and quietly merged them.
        Assert.NotEqual(
            ConnectionKey.For(ConnectionPlanner.Plan(viaAlice)),
            ConnectionKey.For(ConnectionPlanner.Plan(viaBob)));
    }

    [Fact]
    public void A_direct_connection_and_a_bastioned_one_do_not_share_a_key()
    {
        var direct = Target(TenantA);
        var tunnelled = direct with
        {
            Bastion = new BastionHop("jump", 22, Credential, "alice"),
        };

        Assert.NotEqual(
            ConnectionKey.For(ConnectionPlanner.Plan(direct)),
            ConnectionKey.For(ConnectionPlanner.Plan(tunnelled)));
    }

    [Fact]
    public void The_key_carries_no_secret_material()
    {
        var key = ConnectionKey.For(ConnectionPlanner.Plan(Target(TenantA)));

        // Keys are held in a dictionary for the process lifetime and are safe to log by design, so
        // this pins that they stay composed of ids and addresses only.
        Assert.Contains(Credential.Id.ToString(), key, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(TenantA.ToString(), key, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BEGIN", key, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_host_dimension_ignores_tenant_and_credential()
    {
        var a = ConnectionKey.HostKeyFor(ConnectionPlanner.Plan(Target(TenantA)));
        var b = ConnectionKey.HostKeyFor(ConnectionPlanner.Plan(Target(TenantB)));

        // Deliberately the opposite rule from the pool key: a remote host cares how much total work
        // it is being given, not whose it is, so its budget must be shared across tenants.
        Assert.Equal(a, b);
        Assert.Equal("localhost:2201", a);
    }

    [Fact]
    public void The_host_dimension_names_the_bastion_when_one_is_configured()
    {
        var tunnelled = Target(TenantA) with
        {
            Bastion = new BastionHop("jump", 2222, Credential, "alice"),
        };

        // The bastion is the machine actually accepting a socket; the destination is reached through
        // it, so the bastion is the host under load and the one whose budget matters.
        Assert.Equal("jump:2222", ConnectionKey.HostKeyFor(ConnectionPlanner.Plan(tunnelled)));
    }
}
