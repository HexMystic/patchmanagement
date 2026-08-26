using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PatchManagement.Persistence.Migrations
{
    /// <summary>
    /// Phase 4 slice 2: discovery provenance, asset evidence, and the D-301 host-key store.
    ///
    /// THREE NET-NEW TENANT-SCOPED TABLES, plus ONE EDIT to the frozen assets table. The edit —
    /// endpoint_port and ux_assets_discovery_candidate — is the discovery natural key, recorded in
    /// ADR 0024 BEFORE this migration was written because it changes a frozen contract (NEVER #6).
    /// The three tables are additive and seek no RLS exemption; CLAUDE.md §4.1's single named
    /// exemption stays at five global content tables.
    ///
    /// THE GRANTS ARE DELIBERATELY NOT FULL CRUD, which departs from the six existing tenant tables:
    ///   * discovery_runs  SELECT, INSERT, UPDATE — a run is opened then closed, never deleted.
    ///   * asset_evidence  SELECT, INSERT         — append-only, the audit_log posture. An
    ///                                              observation is a fact about a moment; correcting
    ///                                              it means recording a later one. This is what
    ///                                              makes an unmanaged flag explainable (§4.6), so
    ///                                              it must not be editable after the fact.
    ///   * host_keys       SELECT, INSERT, UPDATE — a key is pinned then superseded, never erased.
    ///                                              Deleting the record of what was once trusted
    ///                                              destroys the evidence of a key CHANGE, which is
    ///                                              the security-relevant event the table exists for.
    /// RlsConventionTests asserts each posture, including the absence of DELETE.
    /// </summary>
    public partial class DiscoveryAssetProvenanceAndHostKeys : Migration
    {
        private const string Guc = "app.tenant_id";
        private const string AppRole = "patchmgmt_app";

        private static readonly string[] NewTenantTables =
            { "discovery_runs", "asset_evidence", "host_keys" };

        /// <summary>Grants per table — see the class summary for why these are not uniform.</summary>
        private static readonly (string Table, string Privileges)[] Grants =
        {
            ("discovery_runs", "SELECT, INSERT, UPDATE"),
            ("asset_evidence", "SELECT, INSERT"),
            ("host_keys", "SELECT, INSERT, UPDATE"),
        };

        private static string PolicyPredicate =>
            $"(tenant_id = NULLIF(current_setting('{Guc}', true), '')::uuid)";

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "endpoint_port",
                table: "assets",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "discovery_runs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    outcome = table.Column<string>(type: "text", nullable: false),
                    requested_ranges = table.Column<string>(type: "jsonb", nullable: false),
                    requested_ports = table.Column<string>(type: "jsonb", nullable: false),
                    refused_ranges = table.Column<string>(type: "jsonb", nullable: false),
                    addresses_probed = table.Column<int>(type: "integer", nullable: false),
                    hosts_found = table.Column<int>(type: "integer", nullable: false),
                    detail = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_discovery_runs", x => x.id);
                    table.UniqueConstraint("ak_discovery_runs_tenant_id_id", x => new { x.tenant_id, x.id });
                    table.CheckConstraint("ck_discovery_runs_completion", "(outcome = 'running') = (completed_at IS NULL)");
                    table.CheckConstraint("ck_discovery_runs_outcome", "outcome IN ('running', 'ok', 'refused-by-policy', 'invalid-range', 'failed')");
                    table.CheckConstraint("ck_discovery_runs_refusal_probed_nothing", "outcome NOT IN ('refused-by-policy', 'invalid-range') OR addresses_probed = 0");
                    table.ForeignKey(
                        name: "fk_discovery_runs_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "host_keys",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    host = table.Column<string>(type: "text", nullable: false),
                    port = table.Column<int>(type: "integer", nullable: false),
                    asset_id = table.Column<Guid>(type: "uuid", nullable: true),
                    key_algorithm = table.Column<string>(type: "text", nullable: false),
                    fingerprint_sha256 = table.Column<string>(type: "text", nullable: false),
                    public_key = table.Column<byte[]>(type: "bytea", nullable: false),
                    status = table.Column<string>(type: "text", nullable: false),
                    first_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_verified_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    superseded_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_host_keys", x => x.id);
                    table.CheckConstraint("ck_host_keys_port", "port BETWEEN 1 AND 65535");
                    table.CheckConstraint("ck_host_keys_status", "status IN ('trusted', 'pending', 'superseded', 'revoked')");
                    table.CheckConstraint("ck_host_keys_superseded_at", "(status IN ('superseded', 'revoked')) = (superseded_at IS NOT NULL)");
                    table.CheckConstraint("ck_host_keys_verified_after_first_seen", "last_verified_at >= first_seen_at");
                    table.ForeignKey(
                        name: "fk_host_keys_assets_tenant_id_asset_id",
                        columns: x => new { x.tenant_id, x.asset_id },
                        principalTable: "assets",
                        principalColumns: new[] { "tenant_id", "id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_host_keys_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "asset_evidence",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    asset_id = table.Column<Guid>(type: "uuid", nullable: false),
                    source = table.Column<string>(type: "text", nullable: false),
                    present = table.Column<bool>(type: "boolean", nullable: false),
                    discovery_run_id = table.Column<Guid>(type: "uuid", nullable: true),
                    observed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    address = table.Column<string>(type: "text", nullable: true),
                    port = table.Column<int>(type: "integer", nullable: true),
                    detail = table.Column<string>(type: "jsonb", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_asset_evidence", x => x.id);
                    table.CheckConstraint("ck_asset_evidence_discovery_names_its_run", "(source = 'discovery') = (discovery_run_id IS NOT NULL)");
                    table.CheckConstraint("ck_asset_evidence_source", "source IN ('discovery', 'ad', 'dhcp', 'inventory')");
                    table.ForeignKey(
                        name: "fk_asset_evidence_assets_tenant_id_asset_id",
                        columns: x => new { x.tenant_id, x.asset_id },
                        principalTable: "assets",
                        principalColumns: new[] { "tenant_id", "id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_asset_evidence_discovery_runs_tenant_id_discovery_run_id",
                        columns: x => new { x.tenant_id, x.discovery_run_id },
                        principalTable: "discovery_runs",
                        principalColumns: new[] { "tenant_id", "id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_asset_evidence_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ux_assets_discovery_candidate",
                table: "assets",
                columns: new[] { "tenant_id", "ip", "endpoint_port" },
                unique: true,
                filter: "source = 'discovery' AND ip IS NOT NULL AND endpoint_port IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_asset_evidence_tenant_id_asset_id",
                table: "asset_evidence",
                columns: new[] { "tenant_id", "asset_id" });

            migrationBuilder.CreateIndex(
                name: "ix_asset_evidence_tenant_id_discovery_run_id",
                table: "asset_evidence",
                columns: new[] { "tenant_id", "discovery_run_id" });

            migrationBuilder.CreateIndex(
                name: "ix_asset_evidence_tenant_id_source_present",
                table: "asset_evidence",
                columns: new[] { "tenant_id", "source", "present" });

            migrationBuilder.CreateIndex(
                name: "ix_discovery_runs_tenant_id_started_at",
                table: "discovery_runs",
                columns: new[] { "tenant_id", "started_at" });

            migrationBuilder.CreateIndex(
                name: "ix_host_keys_tenant_id_asset_id",
                table: "host_keys",
                columns: new[] { "tenant_id", "asset_id" });

            migrationBuilder.CreateIndex(
                name: "ix_host_keys_tenant_id_fingerprint_sha256",
                table: "host_keys",
                columns: new[] { "tenant_id", "fingerprint_sha256" });

            migrationBuilder.CreateIndex(
                name: "ux_host_keys_trusted_endpoint",
                table: "host_keys",
                columns: new[] { "tenant_id", "host", "port" },
                unique: true,
                filter: "status = 'trusted'");

            // Tenant isolation, identical in shape to RlsAndRoles: GRANT + ENABLE + FORCE + exactly
            // one policy named tenant_isolation carrying USING and WITH CHECK. NULLIF(..,'') makes an
            // unset GUC deny every row rather than raise a cast error — fail closed.
            foreach (var (table, privileges) in Grants)
                migrationBuilder.Sql($"GRANT {privileges} ON public.{table} TO {AppRole};");

            foreach (var table in NewTenantTables)
            {
                migrationBuilder.Sql($"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;");
                migrationBuilder.Sql($"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;");
                migrationBuilder.Sql(
                    $"CREATE POLICY tenant_isolation ON public.{table} " +
                    $"USING {PolicyPredicate} WITH CHECK {PolicyPredicate};");
            }

            // No grants to patchmgmt_content: none of these is global content (ADR 0010), and that
            // role holds no access to any tenant-scoped table.
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Policies and grants first: DropTable removes them with the table, but being explicit
            // keeps Down readable as the inverse of Up rather than relying on cascade behaviour.
            foreach (var table in NewTenantTables)
            {
                migrationBuilder.Sql($"DROP POLICY IF EXISTS tenant_isolation ON public.{table};");
                migrationBuilder.Sql($"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY;");
                migrationBuilder.Sql($"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY;");
                migrationBuilder.Sql($"REVOKE ALL ON public.{table} FROM {AppRole};");
            }

            migrationBuilder.DropTable(
                name: "asset_evidence");

            migrationBuilder.DropTable(
                name: "host_keys");

            migrationBuilder.DropTable(
                name: "discovery_runs");

            migrationBuilder.DropIndex(
                name: "ux_assets_discovery_candidate",
                table: "assets");

            migrationBuilder.DropColumn(
                name: "endpoint_port",
                table: "assets");
        }
    }
}
