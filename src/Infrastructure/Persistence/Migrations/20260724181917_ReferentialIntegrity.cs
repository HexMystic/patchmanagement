using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PatchManagement.Persistence.Migrations
{
    /// <summary>
    /// Referential integrity (review H3). Phase 1 shipped with ZERO foreign keys; RLS was doing
    /// all the work, and RLS is only a READ barrier. This closes two concrete holes:
    ///
    /// 1. CROSS-TENANT DANGLING REFERENCES. RLS stops tenant A READING tenant B's asset, but
    ///    nothing stopped A WRITING a finding whose asset_id belongs to B (or to no one). The
    ///    composite FKs — (tenant_id, asset_id) -> assets (tenant_id, id) — make that a
    ///    constraint violation at the database, turning the read barrier into a full referential
    ///    barrier. They need UNIQUE (tenant_id, id) on the parents, added here as alternate keys.
    ///
    /// 2. PHANTOM TENANTS. Combined with the unauthenticated X-Tenant-Id header (review H1), a
    ///    caller could invent a GUID and insert rows "belonging" to a tenant that does not exist —
    ///    RLS's WITH CHECK passes because the GUC matches the row. tenant_id -> tenants(id) closes
    ///    this even before authentication exists.
    ///
    /// PostgreSQL runs referential-integrity checks with row security BYPASSED, so these FKs are
    /// enforced despite FORCE ROW LEVEL SECURITY on both sides.
    ///
    /// DELETE BEHAVIOUR IS DELIBERATE, and has a consequence worth stating plainly: CASCADE only
    /// for asset_packages (inventory belongs to its asset); RESTRICT everywhere else, because
    /// findings and audit rows are EVIDENCE and must not be erasable as a side effect of deleting
    /// something else. The consequence is that a tenant with any audit row cannot be deleted, and
    /// an asset with any finding cannot be deleted. That is the correct default for a compliance
    /// product — decommissioning is a lifecycle STATE, not a DELETE — but it means Phase 4 (asset
    /// lifecycle) and any SaaS offboarding story must provide retire/purge flows explicitly.
    ///
    /// findings -> advisories/patches are PLAIN single-column FKs: content is global and has no
    /// tenant component to keep consistent (ADR 0010).
    ///
    /// credentials -> data_keys is optional (data_key_id is NULL until Phase 2 seals the
    /// envelope); PostgreSQL's default MATCH SIMPLE skips the check while it is NULL.
    ///
    /// CORRECT UNTIL M4: audit_log.tenant_id -> tenants(id) blocks auditing an action attempted
    /// against a nonexistent tenant. Added because phantom-tenant writes are the larger risk
    /// today. Review M4 (system-scope audit — Phase 2's KEK rotation is cross-tenant and must be
    /// auditable) will make that column NULLABLE, which stays FK-compatible. Phase 2 must not
    /// treat this constraint as settled.
    /// </summary>
    public partial class ReferentialIntegrity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddUniqueConstraint(
                name: "ak_data_keys_tenant_id_id",
                table: "data_keys",
                columns: new[] { "tenant_id", "id" });

            migrationBuilder.AddUniqueConstraint(
                name: "ak_assets_tenant_id_id",
                table: "assets",
                columns: new[] { "tenant_id", "id" });

            migrationBuilder.CreateIndex(
                name: "ix_findings_advisory_id",
                table: "findings",
                column: "advisory_id");

            migrationBuilder.CreateIndex(
                name: "ix_findings_patch_id",
                table: "findings",
                column: "patch_id");

            migrationBuilder.CreateIndex(
                name: "ix_credentials_tenant_id_data_key_id",
                table: "credentials",
                columns: new[] { "tenant_id", "data_key_id" });

            migrationBuilder.AddForeignKey(
                name: "fk_asset_packages_assets_tenant_id_asset_id",
                table: "asset_packages",
                columns: new[] { "tenant_id", "asset_id" },
                principalTable: "assets",
                principalColumns: new[] { "tenant_id", "id" },
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "fk_asset_packages_tenants_tenant_id",
                table: "asset_packages",
                column: "tenant_id",
                principalTable: "tenants",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_assets_tenants_tenant_id",
                table: "assets",
                column: "tenant_id",
                principalTable: "tenants",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_audit_log_tenants_tenant_id",
                table: "audit_log",
                column: "tenant_id",
                principalTable: "tenants",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_credentials_data_keys_tenant_id_data_key_id",
                table: "credentials",
                columns: new[] { "tenant_id", "data_key_id" },
                principalTable: "data_keys",
                principalColumns: new[] { "tenant_id", "id" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_credentials_tenants_tenant_id",
                table: "credentials",
                column: "tenant_id",
                principalTable: "tenants",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_data_keys_tenants_tenant_id",
                table: "data_keys",
                column: "tenant_id",
                principalTable: "tenants",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_findings_advisories_advisory_id",
                table: "findings",
                column: "advisory_id",
                principalTable: "advisories",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_findings_assets_tenant_id_asset_id",
                table: "findings",
                columns: new[] { "tenant_id", "asset_id" },
                principalTable: "assets",
                principalColumns: new[] { "tenant_id", "id" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_findings_patches_patch_id",
                table: "findings",
                column: "patch_id",
                principalTable: "patches",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_findings_tenants_tenant_id",
                table: "findings",
                column: "tenant_id",
                principalTable: "tenants",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_operators_tenants_tenant_id",
                table: "operators",
                column: "tenant_id",
                principalTable: "tenants",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_asset_packages_assets_tenant_id_asset_id",
                table: "asset_packages");

            migrationBuilder.DropForeignKey(
                name: "fk_asset_packages_tenants_tenant_id",
                table: "asset_packages");

            migrationBuilder.DropForeignKey(
                name: "fk_assets_tenants_tenant_id",
                table: "assets");

            migrationBuilder.DropForeignKey(
                name: "fk_audit_log_tenants_tenant_id",
                table: "audit_log");

            migrationBuilder.DropForeignKey(
                name: "fk_credentials_data_keys_tenant_id_data_key_id",
                table: "credentials");

            migrationBuilder.DropForeignKey(
                name: "fk_credentials_tenants_tenant_id",
                table: "credentials");

            migrationBuilder.DropForeignKey(
                name: "fk_data_keys_tenants_tenant_id",
                table: "data_keys");

            migrationBuilder.DropForeignKey(
                name: "fk_findings_advisories_advisory_id",
                table: "findings");

            migrationBuilder.DropForeignKey(
                name: "fk_findings_assets_tenant_id_asset_id",
                table: "findings");

            migrationBuilder.DropForeignKey(
                name: "fk_findings_patches_patch_id",
                table: "findings");

            migrationBuilder.DropForeignKey(
                name: "fk_findings_tenants_tenant_id",
                table: "findings");

            migrationBuilder.DropForeignKey(
                name: "fk_operators_tenants_tenant_id",
                table: "operators");

            migrationBuilder.DropIndex(
                name: "ix_findings_advisory_id",
                table: "findings");

            migrationBuilder.DropIndex(
                name: "ix_findings_patch_id",
                table: "findings");

            migrationBuilder.DropUniqueConstraint(
                name: "ak_data_keys_tenant_id_id",
                table: "data_keys");

            migrationBuilder.DropIndex(
                name: "ix_credentials_tenant_id_data_key_id",
                table: "credentials");

            migrationBuilder.DropUniqueConstraint(
                name: "ak_assets_tenant_id_id",
                table: "assets");
        }
    }
}
