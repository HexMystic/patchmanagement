using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using PatchManagement.Contracts.States;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Entities;
using PatchManagement.Persistence.Rls;
using Xunit;

namespace PatchManagement.IntegrationTests;

[Collection(PostgresCollection.Name)]
public sealed class RlsTests(PostgresFixture fx)
{
    private static readonly Guid TenantA = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid TenantB = Guid.Parse("22222222-2222-2222-2222-222222222222");

    // Requirement (b): isolation proven through the real HTTP pipeline, as the restricted role.
    [Fact]
    public async Task Rls_isolates_assets_through_the_http_pipeline()
    {
        await SeedAsync();
        await using var factory = new AppFactory(fx.AppConnectionString);
        using var client = factory.CreateClient();

        Assert.Equal(["a-host"], await HostnamesAsync(client, TenantA));
        Assert.Equal(["b-host"], await HostnamesAsync(client, TenantB));
        Assert.Empty(await HostnamesAsync(client, null)); // no tenant -> fail closed
    }

    // Belt-and-suspenders: isolation also holds at the DbContext layer as the restricted role.
    [Fact]
    public async Task Rls_isolates_assets_at_the_dbcontext_as_restricted_role()
    {
        await SeedAsync();
        var tenant = new TenantContextAccessor { TenantId = TenantA };
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(fx.AppConnectionString)
            .AddInterceptors(new RlsConnectionInterceptor(tenant))
            .UseSnakeCaseNamingConvention()
            .Options;

        await using var db = new AppDbContext(options);
        var hosts = await db.Assets.Select(a => a.Hostname).ToListAsync();

        Assert.Equal(["a-host"], hosts);
    }

    // audit_log is append-only for the app role: INSERT allowed, UPDATE denied at the DB.
    [Fact]
    public async Task Audit_log_is_append_only_for_the_app_role()
    {
        await SeedAsync();
        await using var conn = new NpgsqlConnection(fx.AppConnectionString);
        await conn.OpenAsync();

        await ExecAsync(conn, $"SELECT set_config('app.tenant_id','{TenantA}',false)");
        await ExecAsync(conn,
            $"INSERT INTO audit_log(id,tenant_id,actor,action,target,at) " +
            $"VALUES(gen_random_uuid(),'{TenantA}','tester','probe','asset',now())");

        var ex = await Assert.ThrowsAsync<PostgresException>(
            () => ExecAsync(conn, "UPDATE audit_log SET action = 'tamper'"));
        Assert.Equal("42501", ex.SqlState); // insufficient_privilege
    }

    private static async Task ExecAsync(NpgsqlConnection conn, string sql)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<string[]> HostnamesAsync(HttpClient client, Guid? tenant)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/diag/assets");
        if (tenant is { } t) request.Headers.Add("X-Tenant-Id", t.ToString());

        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync();
        using var doc = await JsonDocument.ParseAsync(stream);
        return doc.RootElement.GetProperty("hostnames")
            .EnumerateArray().Select(e => e.GetString()!).ToArray();
    }

    private async Task SeedAsync()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(fx.OwnerConnectionString) // owner/superuser bypasses RLS for seeding
            .UseSnakeCaseNamingConvention()
            .Options;

        await using var db = new AppDbContext(options);
        if (await db.Tenants.AnyAsync()) return; // fixture is shared; seed once

        var now = DateTimeOffset.UtcNow;
        db.Tenants.AddRange(
            new Tenant { Id = TenantA, Name = "Tenant A", Status = "active", CreatedAt = now, UpdatedAt = now },
            new Tenant { Id = TenantB, Name = "Tenant B", Status = "active", CreatedAt = now, UpdatedAt = now });
        db.Assets.AddRange(
            new Asset { Id = Guid.NewGuid(), TenantId = TenantA, Hostname = "a-host", Managed = true, Source = "discovery", State = EndpointState.AssessedMissing, CreatedAt = now, UpdatedAt = now },
            new Asset { Id = Guid.NewGuid(), TenantId = TenantB, Hostname = "b-host", Managed = true, Source = "discovery", State = EndpointState.AssessedMissing, CreatedAt = now, UpdatedAt = now });
        await db.SaveChangesAsync();
    }
}
