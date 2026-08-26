using Microsoft.EntityFrameworkCore;
using Npgsql;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Rls;
using Xunit;

namespace PatchManagement.Discovery.IntegrationTests;

/// <summary>
/// An ephemeral database per test run, migrated from the real migrations and connected as the
/// restricted <c>patchmgmt_app</c> role so RLS is actually in force.
///
/// <para><b>The app role, not the owner, and that is the point.</b> The owner bypasses nothing here
/// — <c>FORCE ROW LEVEL SECURITY</c> applies to the table owner too — but the owner does hold
/// privileges the application never has. Running the store's tests as the role the application
/// actually uses is what makes a passing grant posture mean something.</para>
///
/// <para><b>This is the fourth Postgres fixture in the repo</b> (<c>IntegrationTests</c>,
/// <c>Content.IntegrationTests</c>, <c>Vault.Tests</c>, and now this one). It is duplication, and it
/// is deliberate rather than unnoticed: this project must NOT be merged into
/// <c>PatchManagement.IntegrationTests</c>, because that project deliberately does not reference any
/// module — referencing Discovery would copy its DLL into the test output and make
/// <c>Real_host_container_resolves_the_discovery_module</c> pass on that copy while the shipped API
/// lacked the module. Collapsing the fixtures onto <c>TestSupport</c> is the right fix and is
/// adjacent to <b>D-308</b>; see docs/phases/phase-4.md.</para>
/// </summary>
public sealed class DiscoveryPostgresFixture : IAsyncLifetime
{
    private const string Host = "localhost";
    private const int Port = 5432;
    private const string OwnerUser = "patchmgmt";
    private const string OwnerPassword = "patchmgmt";
    private const string AppUser = "patchmgmt_app";
    private const string AppPassword = "patchmgmt_app_dev";

    private readonly string _dbName = $"pm_discovery_{Guid.NewGuid():N}";

    public string OwnerConnectionString { get; private set; } = string.Empty;
    public string AppConnectionString { get; private set; } = string.Empty;

    public async Task InitializeAsync()
    {
        try
        {
            await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword), $"CREATE DATABASE \"{_dbName}\"");
        }
        catch (NpgsqlException ex)
        {
            throw new InvalidOperationException(
                $"Postgres is not reachable at {Host}:{Port}.{Environment.NewLine}"
                + "Bring the infra up FROM THE MAIN WORKTREE (WORKFLOW.md §3):" + Environment.NewLine
                + "  docker compose up -d",
                ex);
        }

        OwnerConnectionString = Conn(_dbName, OwnerUser, OwnerPassword);
        AppConnectionString = Conn(_dbName, AppUser, AppPassword);

        await using var db = new AppDbContext(Options(OwnerConnectionString, tenant: null));
        await db.Database.MigrateAsync();

        await ExecAsync(OwnerConnectionString, $@"
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{AppUser}') THEN
        CREATE ROLE {AppUser} LOGIN;
    END IF;
END
$$;");
        await ExecAsync(OwnerConnectionString, $"ALTER ROLE {AppUser} WITH LOGIN PASSWORD '{AppPassword}'");
    }

    /// <summary>
    /// A context scoped to <paramref name="tenantId"/> through the same interceptor the host uses,
    /// so these tests exercise the real RLS path rather than a test-only substitute.
    /// </summary>
    public AppDbContext AppContextFor(Guid tenantId) =>
        new(Options(AppConnectionString, tenantId));

    /// <summary>An owner-role context, for asserting what a tenant-scoped caller could not see.</summary>
    public AppDbContext OwnerContext() => new(Options(OwnerConnectionString, tenant: null));

    private static DbContextOptions<AppDbContext> Options(string connectionString, Guid? tenant)
    {
        var accessor = new TenantContextAccessor { TenantId = tenant };

        return new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(connectionString)
            .AddInterceptors(new RlsConnectionInterceptor(accessor))
            .UseSnakeCaseNamingConvention()
            .Options;
    }

    public async Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        try
        {
            await ExecAsync(
                Conn("patchmgmt", OwnerUser, OwnerPassword),
                $"DROP DATABASE IF EXISTS \"{_dbName}\" WITH (FORCE)");
        }
        catch (NpgsqlException)
        {
            // A leaked database in a dev cluster is untidy, not a test failure.
        }
    }

    private static string Conn(string database, string user, string password) =>
        $"Host={Host};Port={Port};Database={database};Username={user};Password={password}";

    private static async Task ExecAsync(string connectionString, string sql)
    {
        await using var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }
}

[CollectionDefinition(Name)]
public sealed class DiscoveryPostgresCollection : ICollectionFixture<DiscoveryPostgresFixture>
{
    public const string Name = "discovery-postgres";
}
