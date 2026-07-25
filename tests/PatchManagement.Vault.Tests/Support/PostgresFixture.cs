using Microsoft.EntityFrameworkCore;
using Npgsql;
using PatchManagement.Persistence;
using PatchManagement.Vault.KeyProviders;
using Xunit;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// Ephemeral-DB fixture — the pattern copied from the IntegrationTests project (Testcontainers is
/// blocked by this host's Application Control policy). Creates a per-run database on the running
/// compose Postgres, migrates it as the OWNER role, and drops it on dispose. Exposes both the owner
/// connection (bypasses RLS — for seeding + cross-tenant KEK rotation) and the restricted app-role
/// connection (RLS enforced — for per-tenant store/resolve).
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime, IVaultDatabaseFixture
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

    /// <summary>
    /// One KEK keyset for every test sharing this database — as in production, where a single KEK
    /// serves many tenants.
    ///
    /// <para>It has to be collection-scoped rather than per-harness because
    /// <c>KekRotationService.RotateAsync</c> is cross-tenant by design: it re-wraps EVERY non-retired
    /// DEK in the database. With a keyset per harness, a DEK left behind by one test class is wrapped
    /// under a keyset the rotation test's provider has never loaded, and rotation fails with
    /// "No KEK version ... is loaded". A shared keyset makes every DEK in the shared database
    /// unwrappable by any test, which is the only self-consistent arrangement here.</para>
    /// </summary>
    public IKeyProvider SharedKeyProvider { get; }

    /// <summary>
    /// The store behind <see cref="SharedKeyProvider"/>. Exposed so a test can build a SECOND
    /// provider over the same store — two providers sharing one store is how a stale cache is
    /// reproduced, and sharing the store keeps every DEK in the database unwrappable by both.
    /// </summary>
    public InMemoryKekSource SharedKekSource { get; } = new();

    public PostgresFixture() => SharedKeyProvider = new SoftwareKeyProvider(SharedKekSource);

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
