using Npgsql;
using Xunit;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Behavioural contract for the global content catalogue and the referential-integrity graph.
///
/// The grain tests are the important ones: they pin the decision in ADR 0011 that a fix statement
/// is identified by (advisory, package, ecosystem, PLATFORM). Get that wrong and Phase 5's first
/// real Ubuntu ingest fails — one USN legitimately fixes the same package at a different version
/// on every supported release.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class ContentCatalogueTests(PostgresFixture fx)
{
    // ---------------------------------------------------------------------------------------
    // Row grain (ADR 0011) — the multi-release case must work, duplicates must not
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The real-world case that a (advisory, package, ecosystem) key would have rejected:
    /// USN-6789-1 fixes openssl at 3.0.2-0ubuntu1.16 on 22.04 and 3.0.13-0ubuntu3.1 on 24.04.
    /// </summary>
    [Fact]
    public async Task One_advisory_can_fix_the_same_package_at_different_versions_per_platform()
    {
        await using var conn = await OpenContentAsync();
        var advisoryId = await InsertAdvisoryAsync(conn, "usn", $"USN-{Guid.NewGuid():N}");

        await InsertAffectsAsync(conn, advisoryId, "openssl", "deb", "ubuntu:22.04", "3.0.2-0ubuntu1.16");
        await InsertAffectsAsync(conn, advisoryId, "openssl", "deb", "ubuntu:24.04", "3.0.13-0ubuntu3.1");

        Assert.Equal(2, await CountAffectsAsync(conn, advisoryId));
    }

    [Fact]
    public async Task The_same_platform_twice_is_rejected_so_reingest_is_idempotent()
    {
        await using var conn = await OpenContentAsync();
        var advisoryId = await InsertAdvisoryAsync(conn, "usn", $"USN-{Guid.NewGuid():N}");

        await InsertAffectsAsync(conn, advisoryId, "openssl", "deb", "ubuntu:22.04", "3.0.2-0ubuntu1.16");

        var ex = await Assert.ThrowsAsync<PostgresException>(() =>
            InsertAffectsAsync(conn, advisoryId, "openssl", "deb", "ubuntu:22.04", "3.0.2-0ubuntu1.16"));

        Assert.Equal("23505", ex.SqlState); // unique_violation
    }

    /// <summary>
    /// NULL platform is the NVD-CPE case. Under PostgreSQL's DEFAULT null-distinct semantics both
    /// rows would insert and the idempotent upsert would silently break; NULLS NOT DISTINCT is
    /// what makes this throw.
    /// </summary>
    [Fact]
    public async Task Two_rows_with_no_platform_collide_because_nulls_are_not_distinct()
    {
        await using var conn = await OpenContentAsync();
        var advisoryId = await InsertAdvisoryAsync(conn, "nvd", $"CVE-{Guid.NewGuid():N}");

        await InsertAffectsAsync(conn, advisoryId, "openssl", "deb", platform: null, "3.0.2-0ubuntu1.16");

        var ex = await Assert.ThrowsAsync<PostgresException>(() =>
            InsertAffectsAsync(conn, advisoryId, "openssl", "deb", platform: null, "3.0.2-0ubuntu1.16"));

        Assert.Equal("23505", ex.SqlState);
    }

    // ---------------------------------------------------------------------------------------
    // Enum vocabulary is a DATABASE contract, not just a C# one (review M8)
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Severity_accepts_unknown_so_a_silent_source_is_never_fabricated()
    {
        await using var conn = await OpenContentAsync();
        var id = await InsertAdvisoryAsync(conn, "nvd", $"CVE-{Guid.NewGuid():N}", severity: "unknown");
        Assert.NotEqual(Guid.Empty, id);
    }

    [Fact]
    public async Task An_invalid_severity_is_rejected_by_the_database()
    {
        await using var conn = await OpenContentAsync();

        var ex = await Assert.ThrowsAsync<PostgresException>(() =>
            InsertAdvisoryAsync(conn, "nvd", $"CVE-{Guid.NewGuid():N}", severity: "catastrophic"));

        Assert.Equal("23514", ex.SqlState); // check_violation
    }

    /// <summary>
    /// The three-valued KEV contract. NOT NULL would collapse "the KEV feed has not been synced"
    /// into "evaluated, not listed" — letting Phase 7 weight a never-run sync as a confirmed
    /// absence. Same dishonesty severity:'unknown' exists to prevent (HARD-PROBLEMS #8).
    /// </summary>
    [Fact]
    public async Task Kev_membership_distinguishes_not_evaluated_from_evaluated_and_absent()
    {
        await using var conn = await OpenContentAsync();

        var notEvaluated = await InsertAdvisoryAsync(conn, "nvd", $"CVE-{Guid.NewGuid():N}");
        var evaluated = await InsertAdvisoryAsync(conn, "nvd", $"CVE-{Guid.NewGuid():N}");
        await ExecAsync(conn, $"UPDATE advisories SET kev_listed = false WHERE id = '{evaluated}'");

        Assert.Null(await ScalarAsync(conn, $"SELECT kev_listed FROM advisories WHERE id = '{notEvaluated}'"));
        Assert.Equal(false, await ScalarAsync(conn, $"SELECT kev_listed FROM advisories WHERE id = '{evaluated}'"));
    }

    /// <summary>
    /// NOT NULL on jsonb accepts '[]'. An empty provenance array is an unattributable score, which
    /// DIFFERENTIATORS #4 forbids — and JSON-schema validation cannot catch it, because Phase 5
    /// writes through EF rather than through the validator.
    /// </summary>
    [Fact]
    public async Task An_advisory_with_empty_provenance_is_rejected()
    {
        await using var conn = await OpenContentAsync();

        var ex = await Assert.ThrowsAsync<PostgresException>(() =>
            InsertAdvisoryAsync(conn, "nvd", $"CVE-{Guid.NewGuid():N}", provenance: "'[]'::jsonb"));

        Assert.Equal("23514", ex.SqlState);
    }

    /// <summary>
    /// KEV and EPSS enrich an advisory; they do not publish one. Admitting them as `source` would
    /// let one CVE exist as three rows with divergent scores under UNIQUE (source, external_id),
    /// while the provenance design assumes ONE merged row carrying several entries.
    /// </summary>
    [Fact]
    public async Task Scoring_overlays_are_not_valid_advisory_publishers()
    {
        await using var conn = await OpenContentAsync();

        foreach (var overlay in new[] { "kev", "epss" })
        {
            var ex = await Assert.ThrowsAsync<PostgresException>(() =>
                InsertAdvisoryAsync(conn, overlay, $"CVE-{Guid.NewGuid():N}"));

            Assert.Equal("23514", ex.SqlState);
        }
    }

    /// <summary>
    /// Real feeds are per-stream: Red Hat publishes OVAL per major version, Ubuntu per release,
    /// Debian per suite. Keying content_sources on `kind` alone would cap the whole deployment at
    /// seven feeds forever.
    /// </summary>
    [Fact]
    public async Task Several_feeds_of_the_same_kind_can_be_registered()
    {
        await using var conn = await OpenContentAsync();
        var kind = "rhsa";
        var suffix = Guid.NewGuid().ToString("N")[..8];

        await InsertContentSourceAsync(conn, kind, $"rhel-8-{suffix}");
        await InsertContentSourceAsync(conn, kind, $"rhel-9-{suffix}");

        var ex = await Assert.ThrowsAsync<PostgresException>(() =>
            InsertContentSourceAsync(conn, kind, $"rhel-9-{suffix}"));

        Assert.Equal("23505", ex.SqlState); // same (kind, instance) is still the upsert key
    }

    [Fact]
    public async Task A_patch_cannot_supersede_itself()
    {
        await using var conn = await OpenContentAsync();
        var patchId = await InsertPatchAsync(conn, $"KB{Random.Shared.Next(1000000, 9999999)}");

        var ex = await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(
            conn,
            "INSERT INTO patch_supersedence (patch_id, superseded_by_patch_id, created_at) "
            + $"VALUES ('{patchId}', '{patchId}', now())"));

        Assert.Equal("23514", ex.SqlState);
    }

    // ---------------------------------------------------------------------------------------
    // Referential integrity (review H3) — as OWNER, so RLS is not what is doing the work
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// H3 failure 2. RLS's WITH CHECK passes when the GUC matches the row, so before this FK an
    /// unauthenticated caller could invent an X-Tenant-Id and create rows for a tenant that does
    /// not exist.
    /// </summary>
    [Fact]
    public async Task An_asset_cannot_belong_to_a_tenant_that_does_not_exist()
    {
        await using var conn = await OpenOwnerAsync();

        var ex = await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(
            conn,
            "INSERT INTO assets (id, tenant_id, hostname, managed, source, state, created_at, updated_at) "
            + $"VALUES (gen_random_uuid(), '{Guid.NewGuid()}', 'phantom', true, 'discovery', "
            + "'assessed-missing', now(), now())"));

        Assert.Equal("23503", ex.SqlState); // foreign_key_violation
    }

    /// <summary>
    /// H3 failure 1, and the reason the FK is COMPOSITE. RLS stops tenant A reading tenant B's
    /// asset; only (tenant_id, asset_id) -> assets (tenant_id, id) stops A writing a finding that
    /// points at one. Runs as owner precisely so RLS cannot be credited for the rejection.
    /// </summary>
    [Fact]
    public async Task A_finding_cannot_reference_an_asset_belonging_to_another_tenant()
    {
        await using var conn = await OpenOwnerAsync();

        var tenantA = await InsertTenantAsync(conn);
        var tenantB = await InsertTenantAsync(conn);
        var assetOfB = await InsertAssetAsync(conn, tenantB);

        var ex = await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(
            conn,
            "INSERT INTO findings (id, tenant_id, asset_id, state, reversible, opened_at, created_at, updated_at) "
            + $"VALUES (gen_random_uuid(), '{tenantA}', '{assetOfB}', 'assessed-missing', false, "
            + "now(), now(), now())"));

        Assert.Equal("23503", ex.SqlState);
    }

    [Fact]
    public async Task A_finding_cannot_reference_an_advisory_that_does_not_exist()
    {
        await using var conn = await OpenOwnerAsync();

        var tenant = await InsertTenantAsync(conn);
        var asset = await InsertAssetAsync(conn, tenant);

        var ex = await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(
            conn,
            "INSERT INTO findings (id, tenant_id, asset_id, advisory_id, state, reversible, "
            + "opened_at, created_at, updated_at) "
            + $"VALUES (gen_random_uuid(), '{tenant}', '{asset}', '{Guid.NewGuid()}', "
            + "'assessed-missing', false, now(), now(), now())"));

        Assert.Equal("23503", ex.SqlState);
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    private async Task<NpgsqlConnection> OpenContentAsync()
    {
        var conn = new NpgsqlConnection(fx.ContentConnectionString);
        await conn.OpenAsync();
        return conn;
    }

    private async Task<NpgsqlConnection> OpenOwnerAsync()
    {
        var conn = new NpgsqlConnection(fx.OwnerConnectionString);
        await conn.OpenAsync();
        return conn;
    }

    /// <summary>Valid provenance — the CHECK constraint rejects an empty array.</summary>
    private const string Provenance =
        """'[{"source":"usn","retrievedAt":"2026-06-01T00:00:00Z"}]'::jsonb""";

    private static async Task<Guid> InsertAdvisoryAsync(
        NpgsqlConnection conn, string source, string externalId, string severity = "high",
        string provenance = Provenance)
    {
        var id = Guid.NewGuid();
        await ExecAsync(
            conn,
            "INSERT INTO advisories (id, source, external_id, title, severity, "
            + "provenance, created_at, updated_at) "
            + $"VALUES ('{id}', '{source}', '{externalId}', 'test advisory', '{severity}', "
            + $"{provenance}, now(), now())");
        return id;
    }

    private static Task InsertAffectsAsync(
        NpgsqlConnection conn, Guid advisoryId, string package, string ecosystem,
        string? platform, string? fixedVersion) =>
        ExecAsync(
            conn,
            "INSERT INTO advisory_affects (id, advisory_id, package_name, ecosystem, platform, "
            + "fixed_version, backported, created_at) "
            + $"VALUES (gen_random_uuid(), '{advisoryId}', '{package}', '{ecosystem}', "
            + $"{Quote(platform)}, {Quote(fixedVersion)}, true, now())");

    private static async Task<Guid> InsertPatchAsync(NpgsqlConnection conn, string vendorId)
    {
        var id = Guid.NewGuid();
        await ExecAsync(
            conn,
            "INSERT INTO patches (id, source, vendor_id, title, reversible, requires_reboot, "
            + "provenance, created_at, updated_at) "
            + $"VALUES ('{id}', 'msrc', '{vendorId}', 'test patch', false, true, "
            + $"{Provenance}, now(), now())");
        return id;
    }

    private static async Task<Guid> InsertTenantAsync(NpgsqlConnection conn)
    {
        var id = Guid.NewGuid();
        await ExecAsync(
            conn,
            "INSERT INTO tenants (id, name, status, created_at, updated_at) "
            + $"VALUES ('{id}', 'fk-test-{id:N}', 'active', now(), now())");
        return id;
    }

    private static async Task<Guid> InsertAssetAsync(NpgsqlConnection conn, Guid tenantId)
    {
        var id = Guid.NewGuid();
        await ExecAsync(
            conn,
            "INSERT INTO assets (id, tenant_id, hostname, managed, source, state, created_at, updated_at) "
            + $"VALUES ('{id}', '{tenantId}', 'host-{id:N}', true, 'discovery', 'assessed-missing', "
            + "now(), now())");
        return id;
    }

    private static Task InsertContentSourceAsync(NpgsqlConnection conn, string kind, string instance) =>
        ExecAsync(
            conn,
            "INSERT INTO content_sources (id, kind, instance, enabled, last_status, created_at, updated_at) "
            + $"VALUES (gen_random_uuid(), '{kind}', '{instance}', true, 'never-run', now(), now())");

    private static async Task<object?> ScalarAsync(NpgsqlConnection conn, string sql)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        var value = await cmd.ExecuteScalarAsync();
        return value is DBNull ? null : value;
    }

    private static async Task<int> CountAffectsAsync(NpgsqlConnection conn, Guid advisoryId)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT count(*) FROM advisory_affects WHERE advisory_id = '{advisoryId}'";
        return Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    private static string Quote(string? value) => value is null ? "NULL" : $"'{value}'";

    private static async Task ExecAsync(NpgsqlConnection conn, string sql)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }
}
