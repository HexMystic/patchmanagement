using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Discovery.IntegrationTests.Fakes;
using PatchManagement.Discovery.Store;
using PatchManagement.Discovery.Sweep;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Entities;
using Xunit;

namespace PatchManagement.Discovery.IntegrationTests;

/// <summary>
/// Phase 4 criteria (c), (g) and (h) against real Postgres, through the restricted app role with
/// RLS in force.
///
/// <para><b>Criterion (h) is asserted on ID STABILITY, not on row counts.</b> "The second run did
/// not add rows" is satisfied by an implementation that deletes and reinserts, by one that
/// no-ops on a duplicate-key violation, and by one that simply failed to write anything the second
/// time. None of those is idempotent in the sense the phase needs: a finding, a package list and an
/// evidence trail all hang off the asset id, so an id that changes between runs silently orphans
/// everything that referenced it. The count staying the same is a consequence of idempotency, not
/// evidence of it.</para>
/// </summary>
[Collection(DiscoveryPostgresCollection.Name)]
public sealed class DiscoveryStoreTests(DiscoveryPostgresFixture fx)
{
    private static readonly Guid TenantA = Guid.Parse("aaaa0000-0000-0000-0000-000000000001");
    private static readonly Guid TenantB = Guid.Parse("bbbb0000-0000-0000-0000-000000000002");

    // ---------------------------------------------------------------------------------------
    // (c) candidates are persisted, unmanaged, with discovery provenance
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_swept_endpoint_becomes_an_unmanaged_discovery_candidate()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(tenant, ("127.0.0.1", 2201));

        var summary = await service.RunAsync(Request(tenant), CancellationToken.None);

        Assert.Equal(SweepOutcome.Ok, summary.Outcome);
        var assetId = Assert.Single(summary.AssetIds);

        await using var db = fx.AppContextFor(tenant);
        var asset = await db.Assets.SingleAsync(a => a.Id == assetId);

        Assert.Equal(AssetSources.Discovery, asset.Source);
        Assert.False(asset.Managed, "a discovered candidate is not managed until it is inventoried");
        Assert.Equal("127.0.0.1", asset.Ip);
        Assert.Equal(2201, asset.EndpointPort);
        Assert.NotNull(asset.LastSeen);
    }

    /// <summary>
    /// A sweep cannot know a hostname — it never logs in — so the column that must be populated
    /// records the address it actually observed rather than inventing a name. ADR 0024's premise,
    /// made visible in the row.
    /// </summary>
    [Fact]
    public async Task A_candidate_records_the_address_it_was_reached_at_rather_than_inventing_a_hostname()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(tenant, ("127.0.0.1", 2201));

        var summary = await service.RunAsync(Request(tenant), CancellationToken.None);

        await using var db = fx.AppContextFor(tenant);
        var asset = await db.Assets.SingleAsync(a => a.Id == summary.AssetIds[0]);

        Assert.Equal("127.0.0.1", asset.Hostname);
    }

    /// <summary>
    /// One candidate per open PORT, not per address — ADR 0024's over-split, and the case the lab
    /// forces: five containers share 127.0.0.1 and are distinguishable only by port.
    /// </summary>
    [Fact]
    public async Task Five_ports_on_one_address_become_five_candidates()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(
            tenant,
            ("127.0.0.1", 2201), ("127.0.0.1", 2202), ("127.0.0.1", 2203),
            ("127.0.0.1", 2204), ("127.0.0.1", 2205));

        var summary = await service.RunAsync(
            Request(tenant, ports: [2201, 2202, 2203, 2204, 2205]), CancellationToken.None);

        Assert.Equal(5, summary.AssetIds.Count);
        Assert.Equal(5, summary.AssetIds.Distinct().Count());

        await using var db = fx.AppContextFor(tenant);
        var ports = await db.Assets.Select(a => a.EndpointPort).OrderBy(p => p).ToListAsync();

        Assert.Equal([2201, 2202, 2203, 2204, 2205], ports);
    }

    // ---------------------------------------------------------------------------------------
    // (h) idempotency — the same rows, with the same ids
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// THE criterion (h) test. Two runs, and the ids must be identical — not merely equal in count.
    /// </summary>
    [Fact]
    public async Task Re_running_a_sweep_writes_the_same_rows_with_the_same_ids()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(tenant, ("127.0.0.1", 2201), ("127.0.0.1", 2202));
        var request = Request(tenant, ports: [2201, 2202]);

        var first = await service.RunAsync(request, CancellationToken.None);
        var second = await service.RunAsync(request, CancellationToken.None);

        Assert.Equal(2, first.AssetIds.Count);
        Assert.Equal(first.AssetIds, second.AssetIds);

        await using var db = fx.AppContextFor(tenant);
        Assert.Equal(2, await db.Assets.CountAsync());

        // And the ids in the table are the ones the first run minted, not a fresh pair that happens
        // to number two.
        var stored = await db.Assets.Select(a => a.Id).OrderBy(i => i).ToListAsync();
        Assert.Equal(first.AssetIds.Order(), stored);
    }

    /// <summary>
    /// The re-run must UPDATE the existing row, not leave it stale. <c>last_seen</c> is what
    /// separates "still there" from "last seen three weeks ago" (HARD-PROBLEMS #10), so an upsert
    /// that conflicts and does nothing would make every asset look abandoned.
    /// </summary>
    [Fact]
    public async Task Re_running_advances_last_seen_on_the_same_row()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(tenant, ("127.0.0.1", 2201));
        var request = Request(tenant);

        var first = await service.RunAsync(request, CancellationToken.None);
        var seenAfterFirst = await LastSeenAsync(tenant, first.AssetIds[0]);

        await Task.Delay(15);
        var second = await service.RunAsync(request, CancellationToken.None);
        var seenAfterSecond = await LastSeenAsync(tenant, second.AssetIds[0]);

        Assert.Equal(first.AssetIds[0], second.AssetIds[0]);
        Assert.True(
            seenAfterSecond > seenAfterFirst,
            $"last_seen did not advance ({seenAfterFirst:O} -> {seenAfterSecond:O}); the upsert "
            + "conflicted and did nothing, so a live host would read as abandoned.");
    }

    /// <summary>
    /// Every run gets its own provenance row even when it changes no asset — otherwise "we swept and
    /// found the same five" is indistinguishable from "we never swept".
    /// </summary>
    [Fact]
    public async Task Every_run_records_its_own_provenance_row()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(tenant, ("127.0.0.1", 2201));
        var request = Request(tenant);

        var first = await service.RunAsync(request, CancellationToken.None);
        var second = await service.RunAsync(request, CancellationToken.None);

        Assert.NotEqual(first.RunId, second.RunId);

        await using var db = fx.AppContextFor(tenant);
        var runs = await db.DiscoveryRuns.OrderBy(r => r.StartedAt).ToListAsync();

        Assert.Equal(2, runs.Count);
        Assert.All(runs, r => Assert.Equal(DiscoveryRunOutcomes.Ok, r.Outcome));
        Assert.All(runs, r => Assert.NotNull(r.CompletedAt));
        Assert.All(runs, r => Assert.Equal(1, r.AddressesProbed));
    }

    // ---------------------------------------------------------------------------------------
    // evidence — criterion (f)'s foundation
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Each_candidate_gets_evidence_naming_the_run_that_found_it()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(tenant, ("127.0.0.1", 2201));

        var summary = await service.RunAsync(Request(tenant), CancellationToken.None);

        await using var db = fx.AppContextFor(tenant);
        var evidence = await db.AssetEvidence.SingleAsync();

        Assert.Equal(summary.AssetIds[0], evidence.AssetId);
        Assert.Equal(AssetSources.Discovery, evidence.Source);
        Assert.True(evidence.Present, "the sweep saw it, so this is a sighting");
        Assert.Equal(summary.RunId, evidence.DiscoveryRunId);
        Assert.Equal("127.0.0.1", evidence.Address);
        Assert.Equal(2201, evidence.Port);
    }

    /// <summary>
    /// Evidence is append-only (the table grants no UPDATE or DELETE), so a second sighting is a
    /// second row. Two runs must therefore leave two observations of one asset — that accumulation
    /// IS the trail.
    /// </summary>
    [Fact]
    public async Task A_second_sighting_appends_evidence_rather_than_replacing_it()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(tenant, ("127.0.0.1", 2201));
        var request = Request(tenant);

        var first = await service.RunAsync(request, CancellationToken.None);
        var second = await service.RunAsync(request, CancellationToken.None);

        await using var db = fx.AppContextFor(tenant);
        var evidence = await db.AssetEvidence.OrderBy(e => e.ObservedAt).ToListAsync();

        Assert.Equal(2, evidence.Count);
        Assert.All(evidence, e => Assert.Equal(first.AssetIds[0], e.AssetId));
        Assert.Equal([first.RunId, second.RunId], evidence.Select(e => e.DiscoveryRunId));
    }

    // ---------------------------------------------------------------------------------------
    // refusal — a refused sweep is still recorded, and writes no assets
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A refusal is provenance too. Recording nothing would make "we were not allowed to sweep that
    /// range" indistinguishable from "we never tried" — and the run row carries the reason.
    /// </summary>
    [Fact]
    public async Task A_refused_sweep_records_the_run_and_writes_no_assets()
    {
        var tenant = await NewTenantAsync();
        var service = ServiceFor(tenant); // allowlist permits loopback only

        var summary = await service.RunAsync(
            Request(tenant) with { Ranges = ["10.0.0.0/30"] }, CancellationToken.None);

        Assert.Equal(SweepOutcome.RefusedByPolicy, summary.Outcome);
        Assert.Empty(summary.AssetIds);

        await using var db = fx.AppContextFor(tenant);
        Assert.Equal(0, await db.Assets.CountAsync());
        Assert.Equal(0, await db.AssetEvidence.CountAsync());

        var run = await db.DiscoveryRuns.SingleAsync();
        Assert.Equal(DiscoveryRunOutcomes.RefusedByPolicy, run.Outcome);
        Assert.Equal(0, run.AddressesProbed);
        Assert.Contains("10.0.0.0/30", run.RefusedRanges, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // (g) tenant scoping — RLS holds for the new tables
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The same address swept by two tenants is two assets, and neither tenant can see the other's —
    /// through the real interceptor and the real policies, as the restricted app role.
    /// </summary>
    [Fact]
    public async Task Two_tenants_sweeping_the_same_address_get_separate_invisible_rows()
    {
        var a = await NewTenantAsync();
        var b = await NewTenantAsync();

        var forA = ServiceFor(a, ("127.0.0.1", 2201));
        var forB = ServiceFor(b, ("127.0.0.1", 2201));

        var runA = await forA.RunAsync(Request(a), CancellationToken.None);
        var runB = await forB.RunAsync(Request(b), CancellationToken.None);

        Assert.NotEqual(runA.AssetIds[0], runB.AssetIds[0]);

        await using (var db = fx.AppContextFor(a))
        {
            Assert.Equal(runA.AssetIds[0], (await db.Assets.SingleAsync()).Id);
            Assert.Equal(runA.RunId, (await db.DiscoveryRuns.SingleAsync()).Id);
            Assert.Equal(runA.AssetIds[0], (await db.AssetEvidence.SingleAsync()).AssetId);
        }

        await using (var db = fx.AppContextFor(b))
        {
            Assert.Equal(runB.AssetIds[0], (await db.Assets.SingleAsync()).Id);
            Assert.Equal(runB.RunId, (await db.DiscoveryRuns.SingleAsync()).Id);
        }
    }

    /// <summary>
    /// The key is per tenant: the partial unique index is on (tenant_id, ip, endpoint_port), so one
    /// tenant re-sweeping must not collide with another tenant's identical coordinate.
    /// </summary>
    [Fact]
    public async Task Re_running_in_one_tenant_does_not_disturb_another_tenants_candidate()
    {
        var a = await NewTenantAsync();
        var b = await NewTenantAsync();

        var runA1 = await ServiceFor(a, ("127.0.0.1", 2201)).RunAsync(Request(a), CancellationToken.None);
        var runB1 = await ServiceFor(b, ("127.0.0.1", 2201)).RunAsync(Request(b), CancellationToken.None);
        var runA2 = await ServiceFor(a, ("127.0.0.1", 2201)).RunAsync(Request(a), CancellationToken.None);

        Assert.Equal(runA1.AssetIds, runA2.AssetIds);

        await using var db = fx.AppContextFor(b);
        Assert.Equal(runB1.AssetIds[0], (await db.Assets.SingleAsync()).Id);
    }

    // ---------------------------------------------------------------------------------------

    private static SweepRequest Request(Guid tenant, IReadOnlyList<int>? ports = null) =>
        new() { TenantId = tenant, Ranges = ["127.0.0.1/32"], Ports = ports ?? [2201] };

    private IDiscoveryService ServiceFor(Guid tenant, params (string Address, int Port)[] open)
    {
        var sweeper = new NetworkSweeper(
            Options.Create(new DiscoverySweepOptions()),
            Options.Create(new DiscoverySecurityOptions { AllowedTargets = ["127.0.0.0/8"] }),
            new FakePortProbe(open),
            NullLogger<NetworkSweeper>.Instance);

        var db = fx.AppContextFor(tenant);
        return new DiscoveryService(
            sweeper,
            new DiscoveryStore(db, TimeProvider.System),
            NullLogger<DiscoveryService>.Instance);
    }

    private async Task<DateTimeOffset> LastSeenAsync(Guid tenant, Guid assetId)
    {
        await using var db = fx.AppContextFor(tenant);
        var asset = await db.Assets.SingleAsync(a => a.Id == assetId);
        return asset.LastSeen!.Value;
    }

    /// <summary>A fresh tenant per test — the FK to <c>tenants</c> requires a real row.</summary>
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
