using Npgsql;
using Xunit;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Freezes the tenant-isolation CONVENTION as an executable contract (review H4).
///
/// Phases 2-13 — several of them running in PARALLEL worktrees — each add tables, and each must
/// remember to (a) carry tenant_id, (b) GRANT to patchmgmt_app, (c) ENABLE + FORCE row security,
/// (d) add the tenant_isolation policy. One forgotten FORCE in one parallel session is a silent
/// cross-tenant leak: the table still WORKS, it just stops being isolated. These tests scan the
/// live catalog so a new table fails by default rather than leaking by default.
///
/// They also pin the ONE sanctioned exception — the global content catalogue (ADR 0010) — as a
/// deliberate, enumerated allowlist rather than a hole. See <see cref="The_only_tables_without_tenant_id_are_the_known_exemptions"/>:
/// a sixth global table cannot appear silently, because the allowlist itself is asserted.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class RlsConventionTests(PostgresFixture fx)
{
    /// <summary>Not tenant-scoped and not content: the root registry and EF's own bookkeeping.</summary>
    private static readonly string[] NonTenantTables = ["tenants", "__EFMigrationsHistory"];

    /// <summary>
    /// The global content catalogue — CLAUDE.md §4.1's single named exemption (ADR 0010).
    /// Adding to this list is a frozen-contract change (CLAUDE.md NEVER #6), not a test fix.
    /// </summary>
    private static readonly string[] GlobalContentTables =
        ["content_sources", "advisories", "advisory_affects", "patches", "patch_supersedence"];

    /// <summary>Every table legitimately allowed to exist without a <c>tenant_id</c> column.</summary>
    private static readonly string[] Exempt = [..NonTenantTables, ..GlobalContentTables];

    private const string AppRole = "patchmgmt_app";
    private const string ContentRole = "patchmgmt_content";

    // ---------------------------------------------------------------------------------------
    // 1. The convention itself
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Every_tenant_scoped_table_has_tenant_id_force_rls_and_an_isolation_policy()
    {
        var offenders = await QueryAsync(
            """
            SELECT c.relname,
                   EXISTS (SELECT 1 FROM pg_attribute a
                           WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnum > 0
                                 AND NOT a.attisdropped)          AS has_tenant_id,
                   c.relrowsecurity                               AS rls_enabled,
                   c.relforcerowsecurity                          AS rls_forced,
                   EXISTS (SELECT 1 FROM pg_policy p
                           WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation'
                                 AND p.polqual IS NOT NULL        -- USING
                                 AND p.polwithcheck IS NOT NULL)  AS has_policy
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> ALL($1)
            ORDER BY c.relname
            """,
            r => new
            {
                Table = r.GetString(0),
                Ok = r.GetBoolean(1) && r.GetBoolean(2) && r.GetBoolean(3) && r.GetBoolean(4),
                Detail = $"tenant_id={r.GetBoolean(1)} enabled={r.GetBoolean(2)} " +
                         $"forced={r.GetBoolean(3)} policy={r.GetBoolean(4)}",
            },
            // Cast to object so this binds as ONE text[] parameter rather than being spread
            // across `params object[]` as seven separate scalars.
            (object)Exempt);

        Assert.NotEmpty(offenders); // guard: a query that returns nothing must not pass silently

        var broken = offenders.Where(o => !o.Ok).Select(o => $"{o.Table}: {o.Detail}").ToArray();
        Assert.True(
            broken.Length == 0,
            "Every tenant-scoped table needs tenant_id + ENABLE + FORCE RLS + a tenant_isolation "
            + "policy with USING and WITH CHECK. Offenders:\n  " + string.Join("\n  ", broken));
    }

    /// <summary>
    /// The anti-drift assertion. If a later phase adds a table without tenant_id, this fails —
    /// forcing whoever added it to either fix the table or justify a new exemption in review.
    /// </summary>
    [Fact]
    public async Task The_only_tables_without_tenant_id_are_the_known_exemptions()
    {
        var withoutTenantId = await QueryAsync(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
              AND NOT EXISTS (SELECT 1 FROM pg_attribute a
                              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
                                    AND a.attnum > 0 AND NOT a.attisdropped)
            ORDER BY c.relname
            """,
            r => r.GetString(0));

        Assert.Equal(Exempt.Order(), withoutTenantId.Order());
    }

    // ---------------------------------------------------------------------------------------
    // 2. The exemption is deliberate, not a gap
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Global_content_tables_have_no_tenant_id_and_no_row_security()
    {
        foreach (var table in GlobalContentTables)
        {
            var rows = await QueryAsync(
                """
                SELECT EXISTS (SELECT 1 FROM pg_attribute a
                               WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
                                     AND a.attnum > 0 AND NOT a.attisdropped),
                       c.relrowsecurity
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relname = $1
                """,
                r => new { HasTenantId = r.GetBoolean(0), Rls = r.GetBoolean(1) },
                table);

            var row = Assert.Single(rows);
            Assert.False(row.HasTenantId, $"{table} is global content and must NOT have tenant_id");
            Assert.False(row.Rls, $"{table} is global content and must NOT have row security");
        }
    }

    /// <summary>
    /// Isolation for global content is by ROLE rather than by row, so the grants ARE the security
    /// boundary: the request path can read content but never write it, and even the ingestion role
    /// cannot delete it (content retires via withdrawn_at).
    /// </summary>
    [Fact]
    public async Task Global_content_grants_are_read_only_for_the_app_role_and_delete_free_for_content()
    {
        foreach (var table in GlobalContentTables)
        {
            Assert.True(await HasPrivilegeAsync(AppRole, table, "SELECT"), $"{AppRole} must read {table}");

            foreach (var write in new[] { "INSERT", "UPDATE", "DELETE" })
            {
                Assert.False(
                    await HasPrivilegeAsync(AppRole, table, write),
                    $"{AppRole} must NOT hold {write} on {table} — a request-path bug would rewrite "
                    + "the content catalogue for every tenant at once");
            }

            Assert.True(await HasPrivilegeAsync(ContentRole, table, "SELECT"), $"{ContentRole} must read {table}");
            Assert.True(await HasPrivilegeAsync(ContentRole, table, "INSERT"), $"{ContentRole} must insert {table}");
            Assert.True(await HasPrivilegeAsync(ContentRole, table, "UPDATE"), $"{ContentRole} must update {table}");
            Assert.False(
                await HasPrivilegeAsync(ContentRole, table, "DELETE"),
                $"{ContentRole} must NOT hold DELETE on {table} — content retires via withdrawn_at");
        }
    }

    /// <summary>Behavioural counterpart: the grant posture actually bites at runtime.</summary>
    [Fact]
    public async Task App_role_cannot_insert_content()
    {
        await using var conn = new NpgsqlConnection(fx.AppConnectionString);
        await conn.OpenAsync();

        var ex = await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(
            conn,
            """
            INSERT INTO advisories (id, source, external_id, title, severity, kev_listed,
                                    provenance, created_at, updated_at)
            VALUES (gen_random_uuid(), 'nvd', 'CVE-2026-0001', 'x', 'unknown', false,
                    '[]'::jsonb, now(), now())
            """));

        Assert.Equal("42501", ex.SqlState); // insufficient_privilege
    }

    // ---------------------------------------------------------------------------------------
    // 3. Role posture (review L5) — two roles now, twice as much to get wrong
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(AppRole)]
    [InlineData(ContentRole)]
    public async Task Application_roles_are_not_superusers_and_do_not_bypass_rls(string role)
    {
        var rows = await QueryAsync(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1",
            r => new { Super = r.GetBoolean(0), Bypass = r.GetBoolean(1) },
            role);

        var row = Assert.Single(rows);
        Assert.False(row.Super, $"{role} must not be a superuser");
        Assert.False(row.Bypass, $"{role} must not hold BYPASSRLS — it would void FORCE RLS");
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    private async Task<List<T>> QueryAsync<T>(string sql, Func<NpgsqlDataReader, T> map, params object[] args)
    {
        await using var conn = new NpgsqlConnection(fx.OwnerConnectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var a in args) cmd.Parameters.AddWithValue(a);

        var results = new List<T>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync()) results.Add(map(reader));
        return results;
    }

    private async Task<bool> HasPrivilegeAsync(string role, string table, string privilege)
    {
        var rows = await QueryAsync(
            "SELECT has_table_privilege($1, $2, $3)",
            r => r.GetBoolean(0),
            role, $"public.{table}", privilege);
        return Assert.Single(rows);
    }

    private static async Task ExecAsync(NpgsqlConnection conn, string sql)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }
}
