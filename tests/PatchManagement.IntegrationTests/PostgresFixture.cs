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

    private readonly string _dbName = "patchmgmt_test_" + Guid.NewGuid().ToString("N")[..12];

    public string OwnerConnectionString { get; private set; } = string.Empty;
    public string AppConnectionString { get; private set; } = string.Empty;

    private static string Conn(string database, string user, string password) =>
        $"Host={Host};Port={Port};Database={database};Username={user};Password={password}";

    public async Task InitializeAsync()
    {
        // CREATE DATABASE must run outside a transaction and against an existing database.
        await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword), $"CREATE DATABASE \"{_dbName}\"");

        OwnerConnectionString = Conn(_dbName, OwnerUser, OwnerPassword);
        AppConnectionString = Conn(_dbName, AppUser, AppPassword);

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(OwnerConnectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();

        // Ensure the cluster-global app role has the expected dev password.
        await ExecAsync(OwnerConnectionString, $"ALTER ROLE {AppUser} WITH LOGIN PASSWORD '{AppPassword}'");
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
