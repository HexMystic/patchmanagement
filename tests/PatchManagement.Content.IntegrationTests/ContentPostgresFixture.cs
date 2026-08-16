using Microsoft.EntityFrameworkCore;
using Npgsql;
using PatchManagement.Persistence;
using Xunit;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// An ephemeral database on the already-running compose Postgres, migrated as the OWNER role and
/// dropped on dispose. (Testcontainers is blocked by this machine's Application Control policy.)
///
/// <para>Only the <c>patchmgmt_content</c> connection is exposed. That is the point rather than an
/// omission: ADR 0010 makes the catalogue writable by that role alone, so a store test that opened
/// an owner connection would prove the SQL runs — not that it runs <em>as the role production uses</em>.
/// A missing grant would then surface for the first time in production.</para>
///
/// <para>Duplicates the shape of <c>PatchManagement.IntegrationTests.PostgresFixture</c>, which
/// cannot simply be shared: <c>PatchManagement.TestSupport</c> is documented as referencing
/// Contracts ONLY (a Persistence reference there would put EF in every consumer's output), and
/// referencing the other test project would drag the API host in. Recorded as <b>D-501</b> rather
/// than left as a silent copy.</para>
/// </summary>
public sealed class ContentPostgresFixture : IAsyncLifetime
{
    private const string Host = "localhost";
    private const int Port = 5432;
    private const string OwnerUser = "patchmgmt";
    private const string OwnerPassword = "patchmgmt";
    private const string ContentUser = "patchmgmt_content";
    private const string ContentPassword = "patchmgmt_content_dev";

    private readonly string _dbName = "patchmgmt_content_test_" + Guid.NewGuid().ToString("N")[..12];

    /// <summary>The content-ingestion role: writes the global catalogue, no tenant tables (ADR 0010).</summary>
    public string ContentConnectionString { get; private set; } = string.Empty;

    private string OwnerConnectionString { get; set; } = string.Empty;

    private static string Conn(string database, string user, string password) =>
        $"Host={Host};Port={Port};Database={database};Username={user};Password={password}";

    public async Task InitializeAsync()
    {
        try
        {
            await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword), $"CREATE DATABASE \"{_dbName}\"");
        }
        catch (NpgsqlException ex)
        {
            throw new InvalidOperationException(
                "Could not reach the compose Postgres at localhost:5432. These are integration tests "
                + "and they fail rather than skip, because a silently-skipped suite looks exactly like "
                + "a passing one. Start the root stack from the MAIN worktree (WORKFLOW.md section 3): "
                + "docker compose up -d",
                ex);
        }

        OwnerConnectionString = Conn(_dbName, OwnerUser, OwnerPassword);
        ContentConnectionString = Conn(_dbName, ContentUser, ContentPassword);

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(OwnerConnectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();

        // Roles are cluster-global, so the migration's grants are re-applied to this database's
        // tables but the role itself may predate it. Guarded: an unguarded CREATE ROLE throws 42710.
        await ExecAsync(OwnerConnectionString, $@"
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ContentUser}') THEN
        CREATE ROLE {ContentUser} LOGIN;
    END IF;
END
$$;");
        await ExecAsync(
            OwnerConnectionString, $"ALTER ROLE {ContentUser} WITH LOGIN PASSWORD '{ContentPassword}'");
    }

    public async Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword),
            $"DROP DATABASE IF EXISTS \"{_dbName}\" WITH (FORCE)");
    }

    /// <summary>Open a connection as the content role — the one ADR 0010 gives catalogue write access.</summary>
    public async Task<NpgsqlConnection> OpenAsync()
    {
        var conn = new NpgsqlConnection(ContentConnectionString);
        await conn.OpenAsync();
        return conn;
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
public sealed class ContentPostgresCollection : ICollectionFixture<ContentPostgresFixture>
{
    public const string Name = "content-postgres";
}
