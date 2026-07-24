using Microsoft.EntityFrameworkCore;
using Npgsql;
using PatchManagement.Persistence;
using Xunit;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// Ephemeral-DB fixture — the pattern copied from the IntegrationTests project (Testcontainers is
/// blocked by this host's Application Control policy). Creates a per-run database on the running
/// compose Postgres, migrates it as the OWNER role, and drops it on dispose. Exposes both the owner
/// connection (bypasses RLS — for seeding + cross-tenant KEK rotation) and the restricted app-role
/// connection (RLS enforced — for per-tenant store/resolve).
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private const string Host = "localhost";
    private const int Port = 5432;
    private const string OwnerUser = "patchmgmt";
    private const string OwnerPassword = "patchmgmt";
    private const string AppUser = "patchmgmt_app";
    private const string AppPassword = "patchmgmt_app_dev";

    private readonly string _dbName = "patchmgmt_vault_test_" + Guid.NewGuid().ToString("N")[..12];

    public string OwnerConnectionString { get; private set; } = string.Empty;
    public string AppConnectionString { get; private set; } = string.Empty;

    private static string Conn(string database, string user, string password) =>
        $"Host={Host};Port={Port};Database={database};Username={user};Password={password}";

    public async Task InitializeAsync()
    {
        await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword), $"CREATE DATABASE \"{_dbName}\"");

        OwnerConnectionString = Conn(_dbName, OwnerUser, OwnerPassword);
        AppConnectionString = Conn(_dbName, AppUser, AppPassword);

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(OwnerConnectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();

        // Roles are cluster-global; ensure the app role exists with the expected dev password.
        await EnsureRoleAsync(AppUser, AppPassword);
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
