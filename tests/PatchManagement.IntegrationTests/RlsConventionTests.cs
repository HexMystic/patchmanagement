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
///
/// KNOWN LIMITS — these scans are not total, and the gaps are recorded rather than implied:
/// <list type="bullet">
///   <item><b>Schema-scoped to <c>public</c>.</b> Nothing here inspects other schemas. When
///   Hangfire lands (Phases 5/8/11) it creates its own <c>hangfire</c> schema holding serialized
///   job arguments — which will contain tenant ids — with no RLS. That needs its own decision and
///   its own test; it is not covered by these.</item>
///   <item><b><c>relkind = 'r'</c> only.</b> A PARTITIONED table (<c>relkind = 'p'</c>) — a natural
///   fit for Phase 13's audit retention — is invisible to both scans, as are partitions created at
///   runtime rather than by a migration.</item>
///   <item>No <c>ALTER DEFAULT PRIVILEGES</c> is set (review H4's second bullet), so a new table
///   gets no grants automatically. That fails CLOSED, which is the right direction, but it means
///   each phase re-adds grants by hand.</item>
/// </list>
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
    public async Task Every_tenant_scoped_table_has_tenant_id_force_rls_and_exactly_one_isolation_policy()
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
                                 AND p.polwithcheck IS NOT NULL)  AS has_policy,
                   (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policy_count
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> ALL($1)
            ORDER BY c.relname
            """,
            r => new
            {
                Table = r.GetString(0),
                Ok = r.GetBoolean(1) && r.GetBoolean(2) && r.GetBoolean(3) && r.GetBoolean(4)
                     && r.GetInt64(5) == 1,
                Detail = $"tenant_id={r.GetBoolean(1)} enabled={r.GetBoolean(2)} " +
                         $"forced={r.GetBoolean(3)} policy={r.GetBoolean(4)} " +
                         $"policy_count={r.GetInt64(5)}",
            },
            // Cast to object so this binds as ONE text[] parameter rather than being spread
            // across `params object[]` as seven separate scalars.
            (object)Exempt);

        Assert.NotEmpty(offenders); // guard: a query that returns nothing must not pass silently

        var broken = offenders.Where(o => !o.Ok).Select(o => $"{o.Table}: {o.Detail}").ToArray();
        Assert.True(
            broken.Length == 0,
            "Every tenant-scoped table needs tenant_id + ENABLE + FORCE RLS + EXACTLY ONE policy, "
            + "named tenant_isolation, with USING and WITH CHECK. The count matters: PostgreSQL ORs "
            + "permissive policies together, so a second policy such as `USING (true)` silently "
            + "defeats isolation while tenant_isolation still exists. Offenders:\n  "
            + string.Join("\n  ", broken));
    }

    /// <summary>
    /// Requirement (b) of the convention — the grants — which the other tests do not cover for
    /// tenant tables. Also re-pins audit_log's append-only posture at the catalog level, so a
    /// future migration that "helpfully" grants UPDATE fails here rather than in Phase 13.
    /// </summary>
    [Fact]
    public async Task Tenant_tables_grant_crud_to_the_app_role_and_audit_log_stays_append_only()
    {
        string[] crudTables =
            ["operators", "credentials", "data_keys", "assets", "asset_packages", "findings"];

        foreach (var table in crudTables)
        {
            foreach (var privilege in new[] { "SELECT", "INSERT", "UPDATE" })
            {
                Assert.True(
                    await HasPrivilegeAsync(AppRole, table, privilege),
                    $"{AppRole} needs {privilege} on {table}");
            }
        }

        Assert.True(await HasPrivilegeAsync(AppRole, "audit_log", "SELECT"));
        Assert.True(await HasPrivilegeAsync(AppRole, "audit_log", "INSERT"));
        Assert.False(
            await HasPrivilegeAsync(AppRole, "audit_log", "UPDATE"),
            "audit_log must stay append-only: no UPDATE for the app role");
        Assert.False(
            await HasPrivilegeAsync(AppRole, "audit_log", "DELETE"),
            "audit_log must stay append-only: no DELETE for the app role");

        // tenants is the root registry: readable, never writable by the app.
        Assert.True(await HasPrivilegeAsync(AppRole, "tenants", "SELECT"));
        Assert.False(await HasPrivilegeAsync(AppRole, "tenants", "INSERT"));
    }

    /// <summary>
    /// Phase 4's three tables carry NON-uniform grants, and the absence of a privilege is the
    /// load-bearing half of each — so it is asserted rather than assumed.
    ///
    /// <para>Every table above this one is full CRUD, which means a migration that granted these
    /// three the same way would look entirely normal in review and silently remove three
    /// guarantees: that a discovery run cannot be deleted, that an observation cannot be edited
    /// after the fact, and that the record of a host key having once been trusted cannot be
    /// erased. The third is the one that matters most — a key CHANGE is the security-relevant
    /// event <c>host_keys</c> exists to capture (D-301), and a DELETE grant would make it
    /// deniable.</para>
    ///
    /// <para>Written as a table of expected privileges rather than as prose assertions so that
    /// adding a fourth table with its own posture is an obvious edit, not a copy-paste.</para>
    /// </summary>
    [Fact]
    public async Task Phase4_tables_carry_their_declared_grant_posture_including_what_is_withheld()
    {
        (string Table, string[] Granted, string[] Withheld)[] posture =
        [
            // A run is opened then closed. Never deleted.
            ("discovery_runs", ["SELECT", "INSERT", "UPDATE"], ["DELETE"]),

            // Append-only, the audit_log posture: an observation is a fact about a moment, and
            // correcting it means recording a later one.
            ("asset_evidence", ["SELECT", "INSERT"], ["UPDATE", "DELETE"]),

            // Pinned, then superseded. Never erased.
            ("host_keys", ["SELECT", "INSERT", "UPDATE"], ["DELETE"]),
        ];

        foreach (var (table, granted, withheld) in posture)
        {
            foreach (var privilege in granted)
            {
                Assert.True(
                    await HasPrivilegeAsync(AppRole, table, privilege),
                    $"{AppRole} needs {privilege} on {table}");
            }

            foreach (var privilege in withheld)
            {
                Assert.False(
                    await HasPrivilegeAsync(AppRole, table, privilege),
                    $"{AppRole} must NOT have {privilege} on {table} — see the migration's summary "
                    + "for why this table is not full CRUD. If the posture genuinely changed, that "
                    + "is a deliberate edit here, not a test to relax.");
            }
        }
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
        // content_sources is deliberately NOT app-readable: its cursor/last_error columns are
        // operational diagnostics that routinely embed internal URLs, and with no RLS every tenant
        // would read every other tenant's infrastructure detail.
        string[] appReadable = ["advisories", "advisory_affects", "patches", "patch_supersedence"];

        Assert.False(
            await HasPrivilegeAsync(AppRole, "content_sources", "SELECT"),
            $"{AppRole} must NOT read content_sources — sync diagnostics are not tenant-visible");

        foreach (var table in appReadable)
        {
            Assert.True(await HasPrivilegeAsync(AppRole, table, "SELECT"), $"{AppRole} must read {table}");
        }

        foreach (var table in GlobalContentTables)
        {
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
            INSERT INTO advisories (id, source, external_id, title, severity,
                                    provenance, created_at, updated_at)
            VALUES (gen_random_uuid(), 'nvd', 'CVE-2026-0001', 'x', 'unknown',
                    '[{"source":"nvd","retrievedAt":"2026-06-01T00:00:00Z"}]'::jsonb, now(), now())
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
