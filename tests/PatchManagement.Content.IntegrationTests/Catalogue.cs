using Npgsql;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// Builders and read-back helpers for the store suite.
///
/// <para>Every builder produces a record that satisfies the frozen CHECK constraints, so a test
/// that goes red has gone red for its own reason rather than for a malformed fixture. Ids are
/// unique per call: the collection shares one database, and a test that collided with its
/// neighbour would fail intermittently and be blamed on the store.</para>
///
/// <para>Read-back goes through raw SQL rather than through the store, deliberately. Asserting a
/// store write by reading it through the same store would pass whenever the write and the read
/// share a mistake — the self-consistency trap that Samples/PROVENANCE.md records for the deleted
/// hand-written fixtures.</para>
/// </summary>
internal static class Catalogue
{
    /// <summary>A short unique suffix, so ids never collide across tests sharing the database.</summary>
    public static string Uid() => Guid.NewGuid().ToString("N")[..10];

    public static ProvenanceEntry Prov(string source, string retrievedAt = "2026-07-29T00:00:00Z") =>
        new(source, DateTimeOffset.Parse(retrievedAt), SourceRecordId: null, Url: null, ContentHash: null);

    public static NormalizedAdvisory Advisory(
        string source,
        string externalId,
        string title = "test advisory",
        string severity = "high",
        double? cvss = null,
        string? cvssSource = null,
        string? retrievedAt = null,
        IReadOnlyList<NormalizedAffect>? affects = null) =>
        new()
        {
            Source = source,
            ExternalId = externalId,
            Title = title,
            Severity = severity,
            CvssBaseScore = cvss,
            CvssSource = cvssSource,
            Provenance = [Prov(source, retrievedAt ?? "2026-07-29T00:00:00Z")],
            Affects = affects ?? [],
        };

    public static NormalizedAffect Affect(
        string package = "openssl",
        string ecosystem = Ecosystems.Deb,
        string? platform = "ubuntu:24.04",
        string? fixedVersion = "3.0.13-0ubuntu3.1",
        bool backported = true) =>
        new(package, ecosystem, platform, fixedVersion, backported);

    public static NormalizedPatch Patch(
        string source,
        string vendorId,
        string title = "test patch",
        bool reversible = false,
        bool requiresReboot = true,
        string? retrievedAt = null,
        IReadOnlyList<string>? supersedes = null) =>
        new()
        {
            Source = source,
            VendorId = vendorId,
            Title = title,
            Reversible = reversible,
            RequiresReboot = requiresReboot,
            Provenance = [Prov(source, retrievedAt ?? "2026-07-29T00:00:00Z")],
            Supersedes = supersedes ?? [],
        };

    // -------------------------------------------------------------------------------------------
    // Transaction plumbing — the store's mutating methods all require the caller's transaction
    // -------------------------------------------------------------------------------------------

    /// <summary>Run <paramref name="work"/> in a committed transaction and return its result.</summary>
    public static async Task<T> CommittedAsync<T>(
        NpgsqlConnection conn, Func<NpgsqlTransaction, Task<T>> work)
    {
        await using var tx = await conn.BeginTransactionAsync();
        var result = await work(tx);
        await tx.CommitAsync();
        return result;
    }

    public static async Task CommittedAsync(NpgsqlConnection conn, Func<NpgsqlTransaction, Task> work)
    {
        await using var tx = await conn.BeginTransactionAsync();
        await work(tx);
        await tx.CommitAsync();
    }

    // -------------------------------------------------------------------------------------------
    // Read-back
    // -------------------------------------------------------------------------------------------

    public static async Task<int> CountAdvisoriesAsync(NpgsqlConnection conn, string externalId) =>
        Convert.ToInt32(await ScalarAsync(
            conn, "SELECT count(*) FROM advisories WHERE external_id = @id", ("id", externalId)));

    public static async Task<int> CountAffectsAsync(NpgsqlConnection conn, Guid advisoryId) =>
        Convert.ToInt32(await ScalarAsync(
            conn, "SELECT count(*) FROM advisory_affects WHERE advisory_id = @id", ("id", advisoryId)));

    public static async Task<object?> AdvisoryFieldAsync(
        NpgsqlConnection conn, Guid advisoryId, string column) =>
        await ScalarAsync(conn, $"SELECT {column} FROM advisories WHERE id = @id", ("id", advisoryId));

    public static async Task<object?> PatchFieldAsync(
        NpgsqlConnection conn, Guid patchId, string column) =>
        await ScalarAsync(conn, $"SELECT {column} FROM patches WHERE id = @id", ("id", patchId));

    /// <summary>The <c>source</c> of every provenance entry on an advisory, in stored order.</summary>
    public static Task<List<string>> AdvisoryProvenanceSourcesAsync(NpgsqlConnection conn, Guid id) =>
        ProvenanceSourcesAsync(conn, "advisories", id);

    public static Task<List<string>> PatchProvenanceSourcesAsync(NpgsqlConnection conn, Guid id) =>
        ProvenanceSourcesAsync(conn, "patches", id);

    private static async Task<List<string>> ProvenanceSourcesAsync(
        NpgsqlConnection conn, string table, Guid id)
    {
        await using var cmd = new NpgsqlCommand(
            $"SELECT e->>'source' FROM {table}, jsonb_array_elements(provenance) e WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);

        var sources = new List<string>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            sources.Add(reader.GetString(0));
        return sources;
    }

    /// <summary>The <c>retrievedAt</c> recorded for one feed's provenance entry, or null if absent.</summary>
    public static async Task<string?> ProvenanceRetrievedAtAsync(
        NpgsqlConnection conn, Guid advisoryId, string source) =>
        (string?)await ScalarAsync(
            conn,
            "SELECT e->>'retrievedAt' FROM advisories, jsonb_array_elements(provenance) e "
            + "WHERE id = @id AND e->>'source' = @source",
            ("id", advisoryId), ("source", source));

    /// <summary>Supersedence edges as (superseded vendor id, superseding vendor id) pairs.</summary>
    public static async Task<List<(string Older, string Newer)>> EdgesAsync(
        NpgsqlConnection conn, string source)
    {
        await using var cmd = new NpgsqlCommand(@"
SELECT older.vendor_id, newer.vendor_id
FROM patch_supersedence ps
JOIN patches older ON older.id = ps.patch_id
JOIN patches newer ON newer.id = ps.superseded_by_patch_id
WHERE older.source = @source
ORDER BY older.vendor_id;", conn);
        cmd.Parameters.AddWithValue("source", source);

        var edges = new List<(string, string)>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            edges.Add((reader.GetString(0), reader.GetString(1)));
        return edges;
    }

    private static async Task<object?> ScalarAsync(
        NpgsqlConnection conn, string sql, params (string Name, object Value)[] parameters)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        foreach (var (name, value) in parameters)
            cmd.Parameters.AddWithValue(name, value);

        var result = await cmd.ExecuteScalarAsync();
        return result is DBNull ? null : result;
    }
}
