using Microsoft.EntityFrameworkCore;
using Npgsql;
using PatchManagement.Persistence;
using Xunit;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Provides an isolated database for the integration tests on the already-running compose
/// Postgres. (Testcontainers is blocked by this machine's Application Control policy, so we
/// create an EPHEMERAL database per run instead, migrate it as the OWNER role, and drop it on
/// dispose.) Roles are cluster-global, so the restricted <c>patchmgmt_app</c> role is reused;
/// the migration re-applies its grants + RLS to the ephemeral database's tables.
/// Exposes the owner connection (for seeding, bypasses RLS) and the restricted app-role
/// connection (RLS enforced).
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private const string Host = "localhost";
    private const int Port = 5432;
    private const string OwnerUser = "patchmgmt";
    private const string OwnerPassword = "patchmgmt";
    private const string AppUser = "patchmgmt_app";
    private const string AppPassword = "patchmgmt_app_dev";
    private const string ContentUser = "patchmgmt_content";
    private const string ContentPassword = "patchmgmt_content_dev";

    private readonly string _dbName = "patchmgmt_test_" + Guid.NewGuid().ToString("N")[..12];

    public string OwnerConnectionString { get; private set; } = string.Empty;
    public string AppConnectionString { get; private set; } = string.Empty;

    /// <summary>The content-ingestion role: writes the global catalogue, no tenant tables (ADR 0010).</summary>
    public string ContentConnectionString { get; private set; } = string.Empty;

    private static string Conn(string database, string user, string password) =>
        $"Host={Host};Port={Port};Database={database};Username={user};Password={password}";

    public async Task InitializeAsync()
    {
        // CREATE DATABASE must run outside a transaction and against an existing database.
        await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword), $"CREATE DATABASE \"{_dbName}\"");

        OwnerConnectionString = Conn(_dbName, OwnerUser, OwnerPassword);
        AppConnectionString = Conn(_dbName, AppUser, AppPassword);
        ContentConnectionString = Conn(_dbName, ContentUser, ContentPassword);

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(OwnerConnectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();

        // Ensure the cluster-global roles exist with the expected dev passwords. Create-if-missing
        // rather than bare ALTER so the fixture does not depend on migration ordering to have
        // created them; guarded because roles outlive this ephemeral database (an unguarded
        // CREATE ROLE throws 42710 on the second run).
        await EnsureRoleAsync(AppUser, AppPassword);
        await EnsureRoleAsync(ContentUser, ContentPassword);
    }

    private async Task EnsureRoleAsync(string role, string password)
    {
        await ExecAsync(OwnerConnectionString, $@"
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
        CREATE ROLE {role} LOGIN;
    END IF;
END
$$;");
        await ExecAsync(OwnerConnectionString, $"ALTER ROLE {role} WITH LOGIN PASSWORD '{password}'");
    }

    public async Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword),
            $"DROP DATABASE IF EXISTS \"{_dbName}\" WITH (FORCE)");
    }

    private static async Task ExecAsync(string connectionString, string sql)
    {
        await using var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }
}

[CollectionDefinition(Name)]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "postgres";
}
