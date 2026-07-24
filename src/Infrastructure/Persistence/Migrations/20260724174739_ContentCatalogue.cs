using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PatchManagement.Persistence.Migrations
{
    /// <summary>
    /// The GLOBAL content catalogue (C1 resolution, ADR 0010): content_sources, advisories,
    /// advisory_affects, patches, patch_supersedence.
    ///
    /// These five tables are the ONE named exemption to CLAUDE.md §4.1 — they carry NO tenant_id
    /// and have NO RLS, because they hold public vendor content that is identical for every
    /// tenant. Isolation here is by ROLE, not by row:
    ///
    ///   patchmgmt_app     -> SELECT on the four tables the request path actually reads.
    ///                        NOT content_sources: its cursor/last_error columns are operational
    ///                        diagnostics that routinely embed internal URLs, and with no RLS
    ///                        every tenant would read them. Phase 5/11 can expose sync status via
    ///                        a projection instead.
    ///   patchmgmt_content -> SELECT, INSERT, UPDATE on all five. No DELETE: content RETIRES via
    ///                        withdrawn_at (same posture as data_keys.retired_at), it never
    ///                        vanishes.
    ///
    /// The exemption is asserted by RlsConventionTests — including that the set of tables lacking
    /// tenant_id is EXACTLY {tenants, __EFMigrationsHistory} + these five — so a sixth global
    /// table cannot appear silently.
    /// </summary>
    public partial class ContentCatalogue : Migration
    {
        private const string AppRole = "patchmgmt_app";
        private const string ContentRole = "patchmgmt_content";

        private static readonly string[] ContentTables =
        {
            "content_sources", "advisories", "advisory_affects", "patches", "patch_supersedence",
        };

        /// <summary>What the request path may read. Excludes content_sources — see the class summary.</summary>
        private static readonly string[] AppReadableTables =
        {
            "advisories", "advisory_affects", "patches", "patch_supersedence",
        };

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "advisories",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    source = table.Column<string>(type: "text", nullable: false),
                    external_id = table.Column<string>(type: "text", nullable: false),
                    title = table.Column<string>(type: "text", nullable: false),
                    severity = table.Column<string>(type: "text", nullable: false),
                    published_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    withdrawn_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    cvss_base_score = table.Column<double>(type: "double precision", nullable: true),
                    cvss_vector = table.Column<string>(type: "text", nullable: true),
                    cvss_version = table.Column<string>(type: "text", nullable: true),
                    cvss_source = table.Column<string>(type: "text", nullable: true),
                    kev_listed = table.Column<bool>(type: "boolean", nullable: true),
                    kev_date_added = table.Column<DateOnly>(type: "date", nullable: true),
                    kev_due_date = table.Column<DateOnly>(type: "date", nullable: true),
                    kev_known_ransomware_use = table.Column<bool>(type: "boolean", nullable: true),
                    epss_score = table.Column<double>(type: "double precision", nullable: true),
                    epss_percentile = table.Column<double>(type: "double precision", nullable: true),
                    epss_scored_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    provenance = table.Column<string>(type: "jsonb", nullable: false),
                    source_metadata = table.Column<string>(type: "jsonb", nullable: true),
                    raw_ref = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_advisories", x => x.id);
                    table.CheckConstraint("ck_advisories_cvss_base_score", "cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)");
                    table.CheckConstraint("ck_advisories_cvss_source", "cvss_source IS NULL OR cvss_source IN ('nvd', 'kev', 'epss', 'usn', 'rhsa', 'msrc', 'wsusscn2')");
                    table.CheckConstraint("ck_advisories_cvss_version", "cvss_version IS NULL OR cvss_version IN ('2.0', '3.0', '3.1', '4.0')");
                    table.CheckConstraint("ck_advisories_epss_percentile", "epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)");
                    table.CheckConstraint("ck_advisories_epss_score", "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)");
                    table.CheckConstraint("ck_advisories_provenance_non_empty", "jsonb_typeof(provenance) = 'array' AND jsonb_array_length(provenance) >= 1");
                    table.CheckConstraint("ck_advisories_severity", "severity IN ('none', 'low', 'medium', 'high', 'critical', 'unknown')");
                    table.CheckConstraint("ck_advisories_source", "source IN ('nvd', 'usn', 'rhsa', 'msrc')");
                });

            migrationBuilder.CreateTable(
                name: "content_sources",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    kind = table.Column<string>(type: "text", nullable: false),
                    instance = table.Column<string>(type: "text", nullable: false),
                    endpoint = table.Column<string>(type: "text", nullable: true),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    last_sync_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    cursor = table.Column<string>(type: "text", nullable: true),
                    last_status = table.Column<string>(type: "text", nullable: false),
                    last_error = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_content_sources", x => x.id);
                    table.CheckConstraint("ck_content_sources_kind", "kind IN ('nvd', 'kev', 'epss', 'usn', 'rhsa', 'msrc', 'wsusscn2')");
                    table.CheckConstraint("ck_content_sources_last_status", "last_status IN ('ok', 'failed', 'never-run')");
                });

            migrationBuilder.CreateTable(
                name: "patches",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    source = table.Column<string>(type: "text", nullable: false),
                    vendor_id = table.Column<string>(type: "text", nullable: false),
                    title = table.Column<string>(type: "text", nullable: false),
                    reversible = table.Column<bool>(type: "boolean", nullable: false),
                    requires_reboot = table.Column<bool>(type: "boolean", nullable: false),
                    classification = table.Column<string>(type: "text", nullable: true),
                    published_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    withdrawn_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    provenance = table.Column<string>(type: "jsonb", nullable: false),
                    source_metadata = table.Column<string>(type: "jsonb", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_patches", x => x.id);
                    table.CheckConstraint("ck_patches_provenance_non_empty", "jsonb_typeof(provenance) = 'array' AND jsonb_array_length(provenance) >= 1");
                    table.CheckConstraint("ck_patches_source", "source IN ('usn', 'rhsa', 'msrc', 'wsusscn2')");
                });

            migrationBuilder.CreateTable(
                name: "advisory_affects",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    advisory_id = table.Column<Guid>(type: "uuid", nullable: false),
                    package_name = table.Column<string>(type: "text", nullable: false),
                    ecosystem = table.Column<string>(type: "text", nullable: false),
                    platform = table.Column<string>(type: "text", nullable: true),
                    fixed_version = table.Column<string>(type: "text", nullable: true),
                    backported = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_advisory_affects", x => x.id);
                    table.CheckConstraint("ck_advisory_affects_ecosystem", "ecosystem IN ('deb', 'rpm', 'windows')");
                    table.ForeignKey(
                        name: "fk_advisory_affects_advisories_advisory_id",
                        column: x => x.advisory_id,
                        principalTable: "advisories",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "patch_supersedence",
                columns: table => new
                {
                    patch_id = table.Column<Guid>(type: "uuid", nullable: false),
                    superseded_by_patch_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_patch_supersedence", x => new { x.patch_id, x.superseded_by_patch_id });
                    table.CheckConstraint("ck_patch_supersedence_no_self_loop", "patch_id <> superseded_by_patch_id");
                    table.ForeignKey(
                        name: "fk_patch_supersedence_patches_patch_id",
                        column: x => x.patch_id,
                        principalTable: "patches",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_patch_supersedence_patches_superseded_by_patch_id",
                        column: x => x.superseded_by_patch_id,
                        principalTable: "patches",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_advisories_source_external_id",
                table: "advisories",
                columns: new[] { "source", "external_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_advisory_affects_advisory_id_package_name_ecosystem_platform",
                table: "advisory_affects",
                columns: new[] { "advisory_id", "package_name", "ecosystem", "platform" },
                unique: true)
                .Annotation("Npgsql:NullsDistinct", false);

            migrationBuilder.CreateIndex(
                name: "ix_advisory_affects_package_name_ecosystem",
                table: "advisory_affects",
                columns: new[] { "package_name", "ecosystem" });

            migrationBuilder.CreateIndex(
                name: "ix_content_sources_kind_instance",
                table: "content_sources",
                columns: new[] { "kind", "instance" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_patch_supersedence_superseded_by_patch_id",
                table: "patch_supersedence",
                column: "superseded_by_patch_id");

            migrationBuilder.CreateIndex(
                name: "ix_patches_source_vendor_id",
                table: "patches",
                columns: new[] { "source", "vendor_id" },
                unique: true);

            // The content-ingestion role (Phase 5 connects as this). Non-owner, non-superuser, no
            // BYPASSRLS. Created WITHOUT a password — provisioned out-of-band (db/roles.sql for
            // dev, the test fixture for CI) so no secret lives in a migration.
            //
            // Guarded: roles are CLUSTER-GLOBAL and outlive the ephemeral per-run test database,
            // so an unguarded CREATE ROLE throws 42710 on the second test run.
            migrationBuilder.Sql($@"
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ContentRole}') THEN
        CREATE ROLE {ContentRole} LOGIN;
    END IF;
END
$$;");
            migrationBuilder.Sql($"GRANT USAGE ON SCHEMA public TO {ContentRole};");

            foreach (var t in AppReadableTables)
            {
                migrationBuilder.Sql($"GRANT SELECT ON public.{t} TO {AppRole};");
            }

            foreach (var t in ContentTables)
            {
                migrationBuilder.Sql($"GRANT SELECT, INSERT, UPDATE ON public.{t} TO {ContentRole};");
            }
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            foreach (var t in ContentTables)
            {
                migrationBuilder.Sql($"REVOKE ALL ON public.{t} FROM {AppRole};");
                migrationBuilder.Sql($"REVOKE ALL ON public.{t} FROM {ContentRole};");
            }

            migrationBuilder.Sql($"REVOKE USAGE ON SCHEMA public FROM {ContentRole};");

            // Deliberately NOT "DROP ROLE patchmgmt_content": roles are CLUSTER-GLOBAL, so
            // reverting THIS database would delete the role out from under every other database in
            // the cluster (including the dev database during a test run). Revoking its grants
            // leaves it harmless; dropping it is a cluster-admin action, not a migration's.

            migrationBuilder.DropTable(
                name: "advisory_affects");

            migrationBuilder.DropTable(
                name: "content_sources");

            migrationBuilder.DropTable(
                name: "patch_supersedence");

            migrationBuilder.DropTable(
                name: "advisories");

            migrationBuilder.DropTable(
                name: "patches");
        }
    }
}
