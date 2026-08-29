using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Connectors;
using PatchManagement.Connectors.DependencyInjection;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Discovery.DependencyInjection;
using PatchManagement.Persistence.Entities;
using PatchManagement.TestSupport.Credentials;
using Xunit;

namespace PatchManagement.Discovery.IntegrationTests;

/// <summary>
/// D-301 — the persistent verified-host-key (TOFU) store, against real containers and real Postgres.
///
/// <para><b>Why this could not be a unit test.</b> The decision logic is unit-tested in
/// <c>HostKeyGateTests</c>, but the property D-301 is actually about is that a key <em>observed from
/// a real handshake</em> is written down, and that the SAME endpoint presenting a DIFFERENT key later
/// is refused. Every interesting part of that — the fingerprint SSH.NET computes from a real key
/// exchange, the row surviving to the next connection, the tenant boundary the database enforces — is
/// absent from a fake.</para>
///
/// <para>This also closes criterion (g) for <c>host_keys</c>: until now the table had RLS and a policy
/// but no writer, so its isolation was proven from the catalog rather than from behaviour. These tests
/// write rows through the restricted <c>patchmgmt_app</c> role with the real
/// <c>RlsConnectionInterceptor</c> in the path.</para>
/// </summary>
[Collection(DiscoveryPostgresCollection.Name)]
public sealed class HostKeyTofuTests(DiscoveryPostgresFixture fx)
{
    private static readonly CredentialRef LabCredential =
        new(Guid.Parse("1ab00000-0000-0000-0000-000000000001"));

    /// <summary>One lab container, addressed the way the fleet publishes it.</summary>
    private const string LabHost = "127.0.0.1";
    private const int LabPort = 2201;

    /// <summary>A fingerprint the lab cannot possibly present, for disagreeing with a host on purpose.</summary>
    private const string NotTheHostsKey = "AAAAthisIsNotTheKeyTheHostHas0000000000000000";

    // -----------------------------------------------------------------------------------
    // Trust on first use — with the persistence that makes it worth anything
    // -----------------------------------------------------------------------------------

    /// <summary>
    /// The first handshake pins whatever the host actually presented — a real fingerprint computed by
    /// the transport from a real key exchange, not a value this test supplied.
    /// </summary>
    [Fact]
    public async Task A_first_handshake_pins_the_key_the_endpoint_actually_presented()
    {
        var tenant = await NewTenantAsync();

        var result = await ConnectAsync(tenant, pinsOnFirstSight: true);
        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);

        var pinned = await SingleKeyAsync(tenant);
        Assert.Equal(HostKeyStatuses.Trusted, pinned.Status);
        Assert.Equal(LabHost, pinned.Host);
        Assert.Equal(LabPort, pinned.Port);

        // Not asserted against a hardcoded value — the lab regenerates host keys on rebuild, so the
        // honest assertion is that a real one was captured, with the public key kept beside it so the
        // fingerprint can be recomputed if the hash of record ever changes.
        Assert.False(string.IsNullOrWhiteSpace(pinned.FingerprintSha256));
        Assert.False(string.IsNullOrWhiteSpace(pinned.KeyAlgorithm));
        Assert.NotEmpty(pinned.PublicKey);
        Assert.Null(pinned.SupersededAt);
    }

    /// <summary>
    /// Reconnecting compares against the pin rather than pinning again — the half that makes this a
    /// verification store and not an observation log. A second trusted row would also mean the store
    /// could no longer answer "which key do we trust" with one row.
    /// </summary>
    [Fact]
    public async Task Reconnecting_verifies_against_the_stored_fingerprint_instead_of_pinning_a_second_key()
    {
        var tenant = await NewTenantAsync();

        Assert.Equal(ConnectorOutcome.Ok, (await ConnectAsync(tenant, pinsOnFirstSight: true)).Outcome);
        var afterFirst = await SingleKeyAsync(tenant);

        Assert.Equal(ConnectorOutcome.Ok, (await ConnectAsync(tenant, pinsOnFirstSight: true)).Outcome);
        var afterSecond = await SingleKeyAsync(tenant);

        Assert.Equal(afterFirst.Id, afterSecond.Id);
        Assert.Equal(afterFirst.FingerprintSha256, afterSecond.FingerprintSha256);
        Assert.Equal(afterFirst.FirstSeenAt, afterSecond.FirstSeenAt);

        // Re-verification is the observable difference between "compared" and "ignored".
        Assert.True(
            afterSecond.LastVerifiedAt >= afterFirst.LastVerifiedAt,
            "reconnecting did not advance last_verified_at, so the pin was never actually consulted");
    }

    // -----------------------------------------------------------------------------------
    // The refusal D-301 exists for
    // -----------------------------------------------------------------------------------

    /// <summary>
    /// <b>The test the deferral names</b> — "a test proving a CHANGED fingerprint is refused".
    ///
    /// <para>The endpoint is pinned to a key it does not have, then contacted. Nothing about the host
    /// changed; what changed is that the store now disagrees with it — which is the shape of a rebuilt
    /// host and of an interception alike. It is refused, and the key it really offered is written down
    /// as pending so the change is auditable afterwards.</para>
    /// </summary>
    [Fact]
    public async Task A_changed_fingerprint_is_refused_and_the_presented_key_is_recorded()
    {
        var tenant = await NewTenantAsync();
        await PinAsync(tenant, "ssh-ed25519", NotTheHostsKey);

        var result = await ConnectAsync(tenant, pinsOnFirstSight: true);

        // Refused DESPITE pinsOnFirstSight: AllowUnknownHostKeys governs pinning something new, not
        // accepting a substitute for something already pinned.
        Assert.Equal(ConnectorOutcome.ProtocolError, result.Outcome);

        await using var db = fx.AppContextFor(tenant);
        var keys = await db.HostKeys.ToListAsync();
        Assert.Equal(2, keys.Count);

        // The bogus pin is untouched. A refusal must not rotate the trust anchor, or anything able to
        // present a key once would replace the pin simply by being refused.
        var pin = Assert.Single(keys, k => k.Status == HostKeyStatuses.Trusted);
        Assert.Equal(NotTheHostsKey, pin.FingerprintSha256);

        var presented = Assert.Single(keys, k => k.Status == HostKeyStatuses.Pending);
        Assert.NotEqual(pin.FingerprintSha256, presented.FingerprintSha256);
        Assert.NotEmpty(presented.PublicKey);
    }

    /// <summary>
    /// Repeated refusals must not grow a row per attempt. A rebuilt host keeps being contacted by
    /// whatever schedule found it, and a table gaining a row each time would bury the one event an
    /// operator needs to see.
    /// </summary>
    [Fact]
    public async Task Repeated_refusals_update_the_pending_row_rather_than_appending_one_per_attempt()
    {
        var tenant = await NewTenantAsync();
        await PinAsync(tenant, "ssh-ed25519", NotTheHostsKey);

        for (var attempt = 0; attempt < 3; attempt++)
        {
            Assert.Equal(
                ConnectorOutcome.ProtocolError,
                (await ConnectAsync(tenant, pinsOnFirstSight: true)).Outcome);
        }

        await using var db = fx.AppContextFor(tenant);
        Assert.Equal(1, await db.HostKeys.CountAsync(k => k.Status == HostKeyStatuses.Pending));
    }

    /// <summary>
    /// With no pin and no permission to create one, the connection is refused — and the key is still
    /// recorded, so promoting it later is a review rather than a re-discovery.
    /// </summary>
    [Fact]
    public async Task An_unpinned_endpoint_is_refused_when_the_deployment_does_not_pin_on_first_sight()
    {
        var tenant = await NewTenantAsync();

        var result = await ConnectAsync(tenant, pinsOnFirstSight: false);

        Assert.Equal(ConnectorOutcome.ProtocolError, result.Outcome);

        var recorded = await SingleKeyAsync(tenant);
        Assert.Equal(HostKeyStatuses.Pending, recorded.Status);
        Assert.NotEmpty(recorded.PublicKey);
    }

    // -----------------------------------------------------------------------------------
    // Criterion (g), behaviourally, for host_keys
    // -----------------------------------------------------------------------------------

    /// <summary>
    /// Two tenants managing the same address each pin independently, and neither can see the other's
    /// row. Until this test, <c>host_keys</c> had a policy but no writer, so its isolation was
    /// asserted from the catalog only.
    /// </summary>
    [Fact]
    public async Task Two_tenants_pinning_the_same_endpoint_get_separate_invisible_rows()
    {
        var first = await NewTenantAsync();
        var second = await NewTenantAsync();

        Assert.Equal(ConnectorOutcome.Ok, (await ConnectAsync(first, pinsOnFirstSight: true)).Outcome);
        Assert.Equal(ConnectorOutcome.Ok, (await ConnectAsync(second, pinsOnFirstSight: true)).Outcome);

        var a = await SingleKeyAsync(first);
        var b = await SingleKeyAsync(second);

        Assert.NotEqual(a.Id, b.Id);
        Assert.Equal(a.FingerprintSha256, b.FingerprintSha256);   // same host, so the same real key

        // Each context sees exactly one row — its own. RLS, through the real interceptor, as the
        // restricted app role.
        await using var asFirst = fx.AppContextFor(first);
        Assert.Equal(1, await asFirst.HostKeys.CountAsync());
        Assert.False(await asFirst.HostKeys.AnyAsync(k => k.Id == b.Id));
    }

    /// <summary>
    /// One tenant's WRONG pin must not refuse another tenant's connection to the same address. That
    /// is the failure a store filtering in C# rather than at the database would produce, and it would
    /// look like an outage rather than like a bug.
    /// </summary>
    [Fact]
    public async Task A_tenants_mismatched_pin_does_not_refuse_another_tenant_at_the_same_address()
    {
        var refused = await NewTenantAsync();
        var unaffected = await NewTenantAsync();

        await PinAsync(refused, "ssh-ed25519", NotTheHostsKey);

        Assert.Equal(
            ConnectorOutcome.ProtocolError,
            (await ConnectAsync(refused, pinsOnFirstSight: true)).Outcome);

        Assert.Equal(
            ConnectorOutcome.Ok,
            (await ConnectAsync(unaffected, pinsOnFirstSight: true)).Outcome);
    }

    // -----------------------------------------------------------------------------------
    // Wiring
    // -----------------------------------------------------------------------------------

    private async Task<ConnectivityResult> ConnectAsync(Guid tenant, bool pinsOnFirstSight)
    {
        var credentials = new FakeCredentialProvider();
        credentials.AddLabKey(LabCredential, "labadmin");

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Connectors:Security:AllowUnknownHostKeys"] = pinsOnFirstSight ? "true" : "false",
                ["Connectors:Concurrency:GlobalMaxConnections"] = "4",
                ["Connectors:Concurrency:PerTenantMaxConnections"] = "4",
                ["Connectors:Concurrency:PerHostMaxConnections"] = "2",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ICredentialProvider>(credentials);
        services.AddScoped(_ => fx.AppContextFor(tenant));

        // AddDiscoveryModule, not a hand-written registration for IHostKeyStore. The module's own
        // registrar is what the shipped host calls, so wiring the store by hand here would leave the
        // path that actually runs in production untested — the unreferenced-module defect in a
        // different costume (criterion (i)).
        services.AddConnectorsModule(configuration);
        services.AddDiscoveryModule(configuration);

        // A FRESH provider per call, because the session pool is a singleton: a pooled session
        // authenticated under an earlier pin would be handed straight back, and the second half of
        // every test here would assert nothing.
        await using var provider = services.BuildServiceProvider(validateScopes: true);
        using var scope = provider.CreateScope();

        var connector = scope.ServiceProvider
            .GetRequiredService<IEndpointConnectorRegistry>()
            .For(EndpointProtocol.Ssh);

        return await connector.TestConnectivityAsync(
            new EndpointTarget
            {
                TenantId = tenant,
                Host = LabHost,
                Port = LabPort,
                Protocol = EndpointProtocol.Ssh,
                Credential = LabCredential,
            },
            CancellationToken.None);
    }

    private async Task<HostKey> SingleKeyAsync(Guid tenant)
    {
        await using var db = fx.AppContextFor(tenant);
        return await db.HostKeys.SingleAsync();
    }

    /// <summary>Writes a trusted pin directly, so a test can disagree with the host on purpose.</summary>
    private async Task PinAsync(Guid tenant, string algorithm, string fingerprint)
    {
        await using var db = fx.AppContextFor(tenant);
        var now = DateTimeOffset.UtcNow;

        db.HostKeys.Add(new HostKey
        {
            Id = Guid.NewGuid(),
            TenantId = tenant,
            Host = LabHost,
            Port = LabPort,
            KeyAlgorithm = algorithm,
            FingerprintSha256 = fingerprint,
            PublicKey = [0x00],
            Status = HostKeyStatuses.Trusted,
            FirstSeenAt = now,
            LastVerifiedAt = now,
            CreatedAt = now,
        });

        await db.SaveChangesAsync();
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
