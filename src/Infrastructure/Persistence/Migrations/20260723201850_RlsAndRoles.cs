using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PatchManagement.Persistence.Migrations
{
    /// <summary>
    /// Establishes tenant isolation: the restricted application role, per-table GRANTs,
    /// ENABLE + FORCE row-level security, and the tenant_isolation policy. Runs as the
    /// migration/owner (superuser) role; the app connects as the non-owner role below.
    ///
    /// The policy compares tenant_id to the app.tenant_id GUC set per connection by
    /// RlsConnectionInterceptor. NULLIF(..,'') makes an unset/empty GUC deny all rows
    /// (fail closed) instead of raising a cast error.
    ///
    /// audit_log is granted SELECT + INSERT only (no UPDATE/DELETE) => append-only.
    /// The app role is created WITHOUT a password here; the password is provisioned
    /// out-of-band (db/roles.sql for dev; the test fixture for CI) so no secret lives in
    /// a migration.
    /// </summary>
    public partial class RlsAndRoles : Migration
    {
        private const string Guc = "app.tenant_id";
        private const string AppRole = "patchmgmt_app";

        private static readonly string[] TenantTables =
        {
            "operators", "credentials", "data_keys", "assets", "asset_packages", "findings",
        };

        private static string PolicyPredicate =>
            $"(tenant_id = NULLIF(current_setting('{Guc}', true), '')::uuid)";

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Restricted, non-owner, non-superuser application role (LOGIN; password set out-of-band).
            migrationBuilder.Sql($@"
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{AppRole}') THEN
        CREATE ROLE {AppRole} LOGIN;
    END IF;
END
$$;");
            migrationBuilder.Sql($"GRANT USAGE ON SCHEMA public TO {AppRole};");

            // tenants is the root registry (no tenant_id / no RLS): read-only for the app.
            migrationBuilder.Sql($"GRANT SELECT ON public.tenants TO {AppRole};");

            // Full-CRUD tenant tables: grant + FORCE RLS + isolation policy.
            foreach (var t in TenantTables)
            {
                migrationBuilder.Sql($"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{t} TO {AppRole};");
                migrationBuilder.Sql($"ALTER TABLE public.{t} ENABLE ROW LEVEL SECURITY;");
                migrationBuilder.Sql($"ALTER TABLE public.{t} FORCE ROW LEVEL SECURITY;");
                migrationBuilder.Sql(
                    $"CREATE POLICY tenant_isolation ON public.{t} " +
                    $"USING {PolicyPredicate} WITH CHECK {PolicyPredicate};");
            }

            // audit_log: append-only (SELECT + INSERT only, no UPDATE/DELETE) + RLS.
            migrationBuilder.Sql($"GRANT SELECT, INSERT ON public.audit_log TO {AppRole};");
            migrationBuilder.Sql("ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;");
            migrationBuilder.Sql("ALTER TABLE public.audit_log FORCE ROW LEVEL SECURITY;");
            migrationBuilder.Sql(
                "CREATE POLICY tenant_isolation ON public.audit_log " +
                $"USING {PolicyPredicate} WITH CHECK {PolicyPredicate};");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            foreach (var t in TenantTables)
            {
                migrationBuilder.Sql($"DROP POLICY IF EXISTS tenant_isolation ON public.{t};");
                migrationBuilder.Sql($"ALTER TABLE public.{t} NO FORCE ROW LEVEL SECURITY;");
                migrationBuilder.Sql($"ALTER TABLE public.{t} DISABLE ROW LEVEL SECURITY;");
                migrationBuilder.Sql($"REVOKE ALL ON public.{t} FROM {AppRole};");
            }

            migrationBuilder.Sql("DROP POLICY IF EXISTS tenant_isolation ON public.audit_log;");
            migrationBuilder.Sql("ALTER TABLE public.audit_log NO FORCE ROW LEVEL SECURITY;");
            migrationBuilder.Sql("ALTER TABLE public.audit_log DISABLE ROW LEVEL SECURITY;");
            migrationBuilder.Sql($"REVOKE ALL ON public.audit_log FROM {AppRole};");

            migrationBuilder.Sql($"REVOKE SELECT ON public.tenants FROM {AppRole};");
            migrationBuilder.Sql($"REVOKE USAGE ON SCHEMA public FROM {AppRole};");
            migrationBuilder.Sql($"DROP ROLE IF EXISTS {AppRole};");
        }
    }
}
