using Microsoft.EntityFrameworkCore;
using Npgsql;
using PatchManagement.Persistence;
using PatchManagement.Vault.KeyProviders;
using Xunit;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// A vault fixture backed by a REAL <see cref="KeyFileKekSource"/> on disk, in its OWN ephemeral
/// database.
///
/// <para>Both halves are necessary. The key file is the point: every other rotation test runs against
/// an in-memory source, so the interaction between the on-disk store and the tenant sweep went
/// untested — which is what let review CR-1 (a rotation destroying every KEK version when the file is
/// absent) reach main-adjacent code. And the separate database is what makes that possible: a sweep
/// visits every tenant in its database, so a file-backed provider sharing the main fixture's database
/// would meet other classes' DEKs sealed under a different keyset, failing them all and making
/// <c>Complete</c> depend on test ordering.</para>
///
/// <para>Same create/migrate/drop pattern as <see cref="PostgresFixture"/> — deliberately duplicated
/// rather than shared, matching how the two test projects already each carry their own copy.</para>
/// </summary>
public sealed class KeyFileVaultFixture : IAsyncLifetime, IVaultDatabaseFixture
{
    private const string Host = "localhost";
    private const int Port = 5432;
    private const string OwnerUser = "patchmgmt";
    private const string OwnerPassword = "patchmgmt";
    private const string AppUser = "patchmgmt_app";
    private const string AppPassword = "patchmgmt_app_dev";

    private readonly string _dbName = "patchmgmt_keyfile_test_" + Guid.NewGuid().ToString("N")[..12];

    public string OwnerConnectionString { get; private set; } = string.Empty;
    public string AppConnectionString { get; private set; } = string.Empty;

    /// <summary>Scratch directory holding the key file, its lock sidecar, and any temp file.</summary>
    public string KeyDirectory { get; } =
        Path.Combine(Path.GetTempPath(), "kek-fixture-" + Guid.NewGuid().ToString("N")[..12]);

    public IKeyProvider SharedKeyProvider { get; private set; } = null!;

    private static string Conn(string database, string user, string password) =>
        $"Host={Host};Port={Port};Database={database};Username={user};Password={password}";

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(KeyDirectory);

        // A genuine first boot, so the opt-in is correct here — and since cold review M7 the opt-in
        // alone is not enough: initialization also needs the arming sentinel, which it consumes.
        var keyPath = Path.Combine(KeyDirectory, "kek.json");
        KekScratch.Arm(keyPath);
        SharedKeyProvider = new SoftwareKeyProvider(new KeyFileKekSource(keyPath, allowInitialize: true));

        await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword), $"CREATE DATABASE \"{_dbName}\"");

        OwnerConnectionString = Conn(_dbName, OwnerUser, OwnerPassword);
        AppConnectionString = Conn(_dbName, AppUser, AppPassword);

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(OwnerConnectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        await ExecAsync(Conn("patchmgmt", OwnerUser, OwnerPassword),
            $"DROP DATABASE IF EXISTS \"{_dbName}\" WITH (FORCE)");

        try { Directory.Delete(KeyDirectory, recursive: true); }
        catch (IOException) { /* best-effort scratch cleanup */ }
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
public sealed class KeyFileVaultCollection : ICollectionFixture<KeyFileVaultFixture>
{
    public const string Name = "keyfile-vault";
}
