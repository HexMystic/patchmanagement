using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Discovery.Correlation;
using PatchManagement.Discovery.IntegrationTests.Fakes;
using PatchManagement.Discovery.Store;
using PatchManagement.Discovery.Sweep;
using PatchManagement.Persistence.Entities;
using Xunit;

namespace PatchManagement.Discovery.IntegrationTests;

/// <summary>
/// Criterion (f) — the differentiator: a host on the network that no inventory claims, flagged
/// <b>with the evidence that explains the flag</b> (<c>DIFFERENTIATORS.md</c> §2, CLAUDE.md §4.6).
///
/// <para><b>The distinction these tests exist to hold.</b> <c>assets.managed = false</c> means "not
/// yet inventoried" — every freshly discovered candidate is that, including ones Active Directory
/// knows perfectly well. An <i>unmanaged asset</i> is something else: seen on the network and
/// corroborated by <b>no</b> other source. Conflating the two turns the differentiator into a list
/// of everything discovery has not got round to yet, which is noise an operator learns to ignore.</para>
///
/// <para>Sources are file-backed and synthetic, which is what criterion (f) asks for — the lab has
/// no AD and no DHCP. Real ingestion is D-401 / D-402.</para>
/// </summary>
[Collection(DiscoveryPostgresCollection.Name)]
public sealed class CorrelationTests(DiscoveryPostgresFixture fx) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("pm-correlation-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    // -----------------------------------------------------------------------------------

    /// <summary>
    /// The headline case. A host the sweep found and nothing else knows about is flagged, and the
    /// flag carries the sighting plus every source that said no.
    /// </summary>
    [Fact]
    public async Task A_host_seen_by_the_sweep_and_in_no_inventory_is_flagged_with_its_evidence()
    {
        var tenant = await NewTenantAsync();
        var run = await SweepAsync(tenant, ("127.0.0.1", 2201));

        var service = CorrelationFor(
            tenant,
            Source("ad"),          // empty — AD does not know it
            Source("dhcp"),        // empty
            Source("inventory"));  // empty

        await service.CorrelateAsync(run.RunId, CancellationToken.None);

        var unmanaged = await service.UnmanagedAsync(CancellationToken.None);
        var flagged = Assert.Single(unmanaged);

        Assert.Equal(run.AssetIds[0], flagged.AssetId);
        Assert.Equal("127.0.0.1", flagged.Address);

        // Explainable: the sighting that found it, and the three sources that did not have it.
        Assert.Contains(flagged.Evidence, e => e.Source == AssetSources.Discovery && e.Present);
        Assert.Equal(["ad", "dhcp", "inventory"], flagged.AbsentFrom);
    }

    /// <summary>
    /// The case that separates an unmanaged asset from an un-inventoried one. This host is in AD, so
    /// it is known — <c>managed = false</c> only means discovery has not logged into it yet.
    /// </summary>
    [Fact]
    public async Task A_host_another_source_knows_about_is_not_flagged_even_though_it_is_unmanaged()
    {
        var tenant = await NewTenantAsync();
        var run = await SweepAsync(tenant, ("127.0.0.1", 2201));

        var service = CorrelationFor(
            tenant,
            Source("ad", "127.0.0.1\tCN=web01,OU=Servers,DC=example,DC=test"),
            Source("dhcp"),
            Source("inventory"));

        await service.CorrelateAsync(run.RunId, CancellationToken.None);

        // The precondition that makes this test meaningful rather than vacuous.
        await using (var db = fx.AppContextFor(tenant))
        {
            Assert.False(await db.Assets.AnyAsync(a => a.Managed));
        }

        Assert.Empty(await service.UnmanagedAsync(CancellationToken.None));
    }

    /// <summary>
    /// Absences must be WRITTEN, not merely computed. The evidence table is append-only and is what
    /// a report is built from, so a flag whose justification exists only in a method's local
    /// variables cannot be audited afterwards.
    /// </summary>
    [Fact]
    public async Task A_source_that_was_consulted_and_said_no_is_recorded_as_an_absence()
    {
        var tenant = await NewTenantAsync();
        var run = await SweepAsync(tenant, ("127.0.0.1", 2201));

        await CorrelationFor(tenant, Source("ad"), Source("dhcp"), Source("inventory"))
            .CorrelateAsync(run.RunId, CancellationToken.None);

        await using var db = fx.AppContextFor(tenant);
        var absences = await db.AssetEvidence.Where(e => !e.Present).ToListAsync();

        Assert.Equal(3, absences.Count);
        Assert.Equal(["ad", "dhcp", "inventory"], absences.Select(e => e.Source).Order(StringComparer.Ordinal));
    }

    /// <summary>A sighting carries the source's own corroboration, so the flag can be traced back.</summary>
    [Fact]
    public async Task A_sighting_records_the_detail_the_source_supplied()
    {
        var tenant = await NewTenantAsync();
        var run = await SweepAsync(tenant, ("127.0.0.1", 2201));

        await CorrelationFor(tenant, Source("dhcp", "127.0.0.1\tlease-42"))
            .CorrelateAsync(run.RunId, CancellationToken.None);

        await using var db = fx.AppContextFor(tenant);
        var dhcp = await db.AssetEvidence.SingleAsync(e => e.Source == "dhcp");

        Assert.True(dhcp.Present);
        // detail is jsonb, so the source's reference is stored wrapped rather than bare.
        Assert.Contains("lease-42", dhcp.Detail!, StringComparison.Ordinal);
    }

    /// <summary>
    /// A source that cannot be consulted must not read as an absence — an unreachable domain
    /// controller would otherwise flag the entire estate as unmanaged, which is an outage reported
    /// as a finding.
    /// </summary>
    [Fact]
    public async Task An_unreadable_source_fails_rather_than_reporting_every_host_absent()
    {
        var tenant = await NewTenantAsync();
        var run = await SweepAsync(tenant, ("127.0.0.1", 2201));

        var missing = new FileBackedEvidenceSource("ad", Path.Combine(_dir, "does-not-exist.txt"));
        var service = CorrelationFor(tenant, missing);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.CorrelateAsync(run.RunId, CancellationToken.None));

        await using var db = fx.AppContextFor(tenant);
        Assert.False(await db.AssetEvidence.AnyAsync(e => e.Source == "ad"));
    }

    /// <summary>Correlation results are tenant-scoped like everything else (criterion g).</summary>
    [Fact]
    public async Task One_tenants_unmanaged_assets_are_invisible_to_another()
    {
        var a = await NewTenantAsync();
        var b = await NewTenantAsync();

        var runA = await SweepAsync(a, ("127.0.0.1", 2201));
        await SweepAsync(b, ("127.0.0.1", 2201));

        await CorrelationFor(a, Source("ad")).CorrelateAsync(runA.RunId, CancellationToken.None);

        var forA = await CorrelationFor(a, Source("ad")).UnmanagedAsync(CancellationToken.None);
        var flagged = Assert.Single(forA);
        Assert.Equal(runA.AssetIds[0], flagged.AssetId);
    }

    // -----------------------------------------------------------------------------------

    private IAssetEvidenceSource Source(string name, params string[] entries)
    {
        var path = Path.Combine(_dir, $"{name}-{Guid.NewGuid():N}.txt");
        File.WriteAllLines(path, entries);
        return new FileBackedEvidenceSource(name, path);
    }

    private ICorrelationService CorrelationFor(Guid tenant, params IAssetEvidenceSource[] sources) =>
        new CorrelationService(
            sources,
            new DiscoveryStore(fx.AppContextFor(tenant), TimeProvider.System),
            NullLogger<CorrelationService>.Instance);

    private async Task<DiscoveryRunSummary> SweepAsync(Guid tenant, params (string Address, int Port)[] open)
    {
        var sweeper = new NetworkSweeper(
            Options.Create(new DiscoverySweepOptions()),
            Options.Create(new DiscoverySecurityOptions { AllowedTargets = ["127.0.0.0/8"] }),
            new FakePortProbe(open),
            NullLogger<NetworkSweeper>.Instance);

        var service = new DiscoveryService(
            sweeper,
            new DiscoveryStore(fx.AppContextFor(tenant), TimeProvider.System),
            NullLogger<DiscoveryService>.Instance);

        return await service.RunAsync(
            new SweepRequest
            {
                TenantId = tenant,
                Ranges = ["127.0.0.1/32"],
                Ports = [.. open.Select(o => o.Port)],
            },
            CancellationToken.None);
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
