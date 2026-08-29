using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Connectors.DependencyInjection;
using PatchManagement.Connectors;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Contracts.States;
using PatchManagement.Discovery.Inventory;
using PatchManagement.Discovery.Store;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Entities;
using PatchManagement.TestSupport.Credentials;
using Xunit;

namespace PatchManagement.Discovery.IntegrationTests;

/// <summary>
/// Criteria (d) and (e) against the real lab fleet over real SSH, persisting into real Postgres.
///
/// <para><b>Criterion (e) is proven by a real rejection, not by a mapping table.</b> The connector
/// already maps <c>AuthFailed</c> to <c>auth-failed</c> in C#, and a unit test asserting that maps a
/// constant to a constant. What was unproven is that a host which actually refuses a credential is
/// classified as a rejection rather than as a timeout — which is precisely what HARD-PROBLEMS #12
/// records going wrong once already: the lab's sshd takes ~10s to reject an unauthorised key, and
/// under a single budget the connector reported <c>Timeout</c> for what was a rejection.</para>
/// </summary>
[Collection(DiscoveryPostgresCollection.Name)]
public sealed class LabInventoryTests(DiscoveryPostgresFixture fx)
{
    private static readonly CredentialRef LabCredential =
        new(Guid.Parse("1ab00000-0000-0000-0000-000000000001"));

    private static readonly CredentialRef WrongCredential =
        new(Guid.Parse("1ab00000-0000-0000-0000-0000000000ff"));

    /// <summary>The fleet, as published by lab/docker-compose.yml.</summary>
    public static TheoryData<string, int, string, string> Fleet => new()
    {
        { "ubuntu2204", 2201, "debian", "dpkg" },
        { "ubuntu2404", 2202, "debian", "dpkg" },
        { "debian12",   2203, "debian", "dpkg" },
        { "rocky9",     2204, "rhel",   "rpm"  },
        { "alma9",      2205, "rhel",   "rpm"  },
    };

    // -----------------------------------------------------------------------------------
    // (d) inventory, per distro
    // -----------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Fleet))]
    public async Task Inventory_populates_packages_and_os_release_for_every_distro(
        string name, int port, string expectedFamily, string expectedManager)
    {
        var tenant = await NewTenantAsync();
        var assetId = await SeedCandidateAsync(tenant, port);

        var result = await ServiceFor(tenant).InventoryAsync(
            assetId, TargetFor(tenant, port), CancellationToken.None);

        Assert.True(result.Succeeded, $"{name}: {result.Outcome} {result.Detail}");
        Assert.Equal(expectedFamily, result.OsFamily);
        Assert.False(string.IsNullOrWhiteSpace(result.OsVersion), $"{name} reported no VERSION_ID");

        await using var db = fx.AppContextFor(tenant);
        var asset = await db.Assets.SingleAsync(a => a.Id == assetId);

        Assert.True(asset.Managed, "a successfully inventoried asset is managed");
        Assert.Equal(expectedFamily, asset.OsFamily);
        Assert.Equal(result.OsVersion, asset.OsVersion);

        var packages = await db.AssetPackages.Where(p => p.AssetId == assetId).ToListAsync();

        // A real distro has hundreds. A handful would mean the listing was truncated or misparsed.
        Assert.True(packages.Count > 50, $"{name} reported only {packages.Count} packages");
        Assert.Equal(result.PackagesRecorded, packages.Count);
        Assert.All(packages, p => Assert.Equal(expectedManager, p.Source));
        Assert.All(packages, p => Assert.False(string.IsNullOrWhiteSpace(p.Name)));
        Assert.All(packages, p => Assert.False(string.IsNullOrWhiteSpace(p.Version)));
        Assert.All(packages, p => Assert.False(string.IsNullOrWhiteSpace(p.Arch)));
    }

    /// <summary>
    /// The epoch is stored SEPARATELY from the version because it dominates comparison and is
    /// invisible in the version text (HARD-PROBLEMS #3). RPM distros publish epochs; losing them
    /// here would make Phase 6 compare <c>2.3</c> against <c>1:2.3</c> as the same release.
    /// </summary>
    [Theory]
    [InlineData("rocky9", 2204)]
    [InlineData("alma9", 2205)]
    public async Task An_rpm_epoch_is_split_out_rather_than_left_in_the_version_string(
        string name, int port)
    {
        var tenant = await NewTenantAsync();
        var assetId = await SeedCandidateAsync(tenant, port);

        await ServiceFor(tenant).InventoryAsync(assetId, TargetFor(tenant, port), CancellationToken.None);

        await using var db = fx.AppContextFor(tenant);
        var packages = await db.AssetPackages.Where(p => p.AssetId == assetId).ToListAsync();

        Assert.True(
            packages.Any(p => p.Epoch is not null),
            $"{name} recorded no epoch on any package; every RPM distro ships some, so the split "
            + "did not happen and the epoch is buried in the version string.");

        Assert.All(packages, p => Assert.DoesNotContain(':', p.Version));
    }

    /// <summary>
    /// Re-inventorying REPLACES the package set. Merging would leave a removed package in the
    /// inventory forever, and Phase 6 would assess the host against software it no longer has.
    /// </summary>
    [Fact]
    public async Task Re_inventorying_replaces_the_package_set_rather_than_accumulating_it()
    {
        var tenant = await NewTenantAsync();
        var assetId = await SeedCandidateAsync(tenant, 2201);
        var target = TargetFor(tenant, 2201);

        var first = await ServiceFor(tenant).InventoryAsync(assetId, target, CancellationToken.None);
        var second = await ServiceFor(tenant).InventoryAsync(assetId, target, CancellationToken.None);

        Assert.Equal(first.PackagesRecorded, second.PackagesRecorded);

        await using var db = fx.AppContextFor(tenant);
        Assert.Equal(
            second.PackagesRecorded,
            await db.AssetPackages.CountAsync(p => p.AssetId == assetId));
    }

    // -----------------------------------------------------------------------------------
    // (e) honest failure states, each proven against a real host
    // -----------------------------------------------------------------------------------

    /// <summary>
    /// A real host that really rejects a real key. This is the criterion (e) test: <c>auth-failed</c>
    /// must be distinguishable from <c>unreachable</c>, and from the <c>scan-failed</c> that a
    /// catch-all would produce.
    /// </summary>
    [Fact]
    public async Task A_wrong_key_against_a_live_host_is_auth_failed_not_unreachable_or_scan_failed()
    {
        var tenant = await NewTenantAsync();
        var assetId = await SeedCandidateAsync(tenant, 2201);

        var target = TargetFor(tenant, 2201) with { Credential = WrongCredential };
        var result = await ServiceFor(tenant).InventoryAsync(assetId, target, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.AuthFailed, result.Outcome);
        Assert.Equal(EndpointState.AuthFailed, result.State);

        Assert.NotEqual(EndpointState.Unreachable, result.State);
        Assert.NotEqual(EndpointState.ScanFailed, result.State);

        await using var db = fx.AppContextFor(tenant);
        var asset = await db.Assets.SingleAsync(a => a.Id == assetId);

        Assert.Equal(EndpointState.AuthFailed, asset.State);
        Assert.False(asset.Managed, "a host we could not log into is not managed");
        Assert.Empty(await db.AssetPackages.Where(p => p.AssetId == assetId).ToListAsync());
    }

    /// <summary>
    /// The other side of the same distinction: nothing listening is <c>unreachable</c>, which sends
    /// someone to the network team rather than to whoever holds credentials.
    /// </summary>
    [Fact]
    public async Task A_closed_port_is_unreachable_not_auth_failed()
    {
        var tenant = await NewTenantAsync();
        var closedPort = ReserveThenReleasePort();
        var assetId = await SeedCandidateAsync(tenant, closedPort);

        var result = await ServiceFor(tenant).InventoryAsync(
            assetId, TargetFor(tenant, closedPort), CancellationToken.None);

        Assert.Equal(EndpointState.Unreachable, result.State);
        Assert.NotEqual(EndpointState.AuthFailed, result.State);

        await using var db = fx.AppContextFor(tenant);
        Assert.Equal(EndpointState.Unreachable, (await db.Assets.SingleAsync(a => a.Id == assetId)).State);
    }

    /// <summary>
    /// A failed inventory must NOT advance <c>last_seen</c> — we did not see it. Otherwise an
    /// unreachable host would never age into staleness (HARD-PROBLEMS #10).
    /// </summary>
    [Fact]
    public async Task A_failed_inventory_does_not_advance_last_seen()
    {
        var tenant = await NewTenantAsync();
        var closedPort = ReserveThenReleasePort();
        var assetId = await SeedCandidateAsync(tenant, closedPort);

        DateTimeOffset before;
        await using (var db = fx.AppContextFor(tenant))
        {
            before = (await db.Assets.SingleAsync(a => a.Id == assetId)).LastSeen!.Value;
        }

        await ServiceFor(tenant).InventoryAsync(
            assetId, TargetFor(tenant, closedPort), CancellationToken.None);

        await using var after = fx.AppContextFor(tenant);
        var asset = await after.Assets.SingleAsync(a => a.Id == assetId);

        Assert.Equal(before, asset.LastSeen);
    }

    /// <summary>
    /// The success path deliberately leaves <c>state</c> alone. The frozen Phase-1 machine has no
    /// "inventoried" state, and assessment is the only thing entitled to decide compliance — so a
    /// successful inventory is recorded as <c>managed = true</c>, not as a state transition.
    /// </summary>
    [Fact]
    public async Task A_successful_inventory_does_not_invent_a_compliance_state()
    {
        var tenant = await NewTenantAsync();
        var assetId = await SeedCandidateAsync(tenant, 2201);

        var result = await ServiceFor(tenant).InventoryAsync(
            assetId, TargetFor(tenant, 2201), CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Null(result.State);

        await using var db = fx.AppContextFor(tenant);
        var asset = await db.Assets.SingleAsync(a => a.Id == assetId);

        Assert.Equal(EndpointState.ScanFailed, asset.State); // as seeded — untouched
        Assert.True(asset.Managed);
    }

    // -----------------------------------------------------------------------------------

    /// <summary>
    /// Composes the connector through <c>AddConnectorsModule</c> rather than by hand.
    ///
    /// <para>Two reasons, and the second is the one that matters. It keeps the connector's internals
    /// internal — this project has no <c>InternalsVisibleTo</c> from that module, and widening one to
    /// let a test reach in would be the wrong direction. And it exercises the real registration, so a
    /// lifetime mistake of the kind that once stopped the Connectors module resolving at all shows up
    /// here rather than only in the host.</para>
    /// </summary>
    private IInventoryService ServiceFor(Guid tenant)
    {
        var credentials = new FakeCredentialProvider();
        credentials.AddLabKey(LabCredential);
        // A syntactically valid key the fleet does not trust: the far end must REJECT it, which is a
        // different event from failing to parse it, and only the rejection proves criterion (e).
        credentials.Add(WrongCredential, GenerateUntrustedKey, CredentialKind.SshKey, "labadmin");

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // The lab rebuilds its containers constantly and they regenerate host keys each
                // time, so there is nothing stable to pin. The product default REFUSES unknown keys;
                // this opt-in is explicit and scoped to the lab. Since D-301 closed it means "pin on
                // first sight" rather than "accept anything" — a changed key is refused here too.
                ["Connectors:Security:AllowUnknownHostKeys"] = "true",
                ["Connectors:Concurrency:GlobalMaxConnections"] = "8",
                ["Connectors:Concurrency:PerTenantMaxConnections"] = "8",
                ["Connectors:Concurrency:PerHostMaxConnections"] = "4",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ICredentialProvider>(credentials);
        services.AddConnectorsModule(configuration);

        var provider = services.BuildServiceProvider(validateScopes: true);
        var scope = provider.CreateScope();

        return new InventoryService(
            scope.ServiceProvider.GetRequiredService<IEndpointConnectorRegistry>(),
            new DiscoveryStore(fx.AppContextFor(tenant), TimeProvider.System),
            NullLogger<InventoryService>.Instance);
    }

    private static EndpointTarget TargetFor(Guid tenant, int port) => new()
    {
        TenantId = tenant,
        Host = "127.0.0.1",
        Port = port,
        Protocol = EndpointProtocol.Ssh,
        Credential = LabCredential,
    };

    private static byte[] GenerateUntrustedKey()
    {
        // Generated per call so it can never coincide with anything the fleet authorises.
        var key = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        return System.Text.Encoding.ASCII.GetBytes(
            "-----BEGIN PRIVATE KEY-----\n"
            + Convert.ToBase64String(key.ExportPkcs8PrivateKey(), Base64FormattingOptions.InsertLineBreaks)
            + "\n-----END PRIVATE KEY-----\n");
    }

    private static int ReserveThenReleasePort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        listener.Dispose();
        return port;
    }

    private async Task<Guid> SeedCandidateAsync(Guid tenant, int port)
    {
        var id = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        await using var db = fx.AppContextFor(tenant);
        db.Assets.Add(new Asset
        {
            Id = id,
            TenantId = tenant,
            Hostname = "127.0.0.1",
            Ip = "127.0.0.1",
            EndpointPort = port,
            Managed = false,
            Source = AssetSources.Discovery,
            State = EndpointState.ScanFailed,
            LastSeen = now,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
        return id;
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
