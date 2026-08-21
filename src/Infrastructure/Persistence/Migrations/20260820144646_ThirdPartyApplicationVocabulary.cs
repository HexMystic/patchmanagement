using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PatchManagement.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ThirdPartyApplicationVocabulary : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_patches_source",
                table: "patches");

            migrationBuilder.DropCheckConstraint(
                name: "ck_content_sources_kind",
                table: "content_sources");

            migrationBuilder.DropCheckConstraint(
                name: "ck_advisory_affects_ecosystem",
                table: "advisory_affects");

            migrationBuilder.DropCheckConstraint(
                name: "ck_advisories_cvss_source",
                table: "advisories");

            migrationBuilder.DropCheckConstraint(
                name: "ck_advisories_source",
                table: "advisories");

            migrationBuilder.AddCheckConstraint(
                name: "ck_patches_source",
                table: "patches",
                sql: "source IN ('usn', 'rhsa', 'msrc', 'wsusscn2', 'dsa', 'vendor')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_content_sources_kind",
                table: "content_sources",
                sql: "kind IN ('nvd', 'kev', 'epss', 'usn', 'rhsa', 'msrc', 'wsusscn2', 'dsa', 'vendor')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_advisory_affects_ecosystem",
                table: "advisory_affects",
                sql: "ecosystem IN ('deb', 'rpm', 'windows', 'app')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_advisories_cvss_source",
                table: "advisories",
                sql: "cvss_source IS NULL OR cvss_source IN ('nvd', 'kev', 'epss', 'usn', 'rhsa', 'msrc', 'wsusscn2', 'dsa', 'vendor')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_advisories_source",
                table: "advisories",
                sql: "source IN ('nvd', 'usn', 'rhsa', 'msrc', 'dsa', 'vendor')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_patches_source",
                table: "patches");

            migrationBuilder.DropCheckConstraint(
                name: "ck_content_sources_kind",
                table: "content_sources");

            migrationBuilder.DropCheckConstraint(
                name: "ck_advisory_affects_ecosystem",
                table: "advisory_affects");

            migrationBuilder.DropCheckConstraint(
                name: "ck_advisories_cvss_source",
                table: "advisories");

            migrationBuilder.DropCheckConstraint(
                name: "ck_advisories_source",
                table: "advisories");

            migrationBuilder.AddCheckConstraint(
                name: "ck_patches_source",
                table: "patches",
                sql: "source IN ('usn', 'rhsa', 'msrc', 'wsusscn2', 'dsa')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_content_sources_kind",
                table: "content_sources",
                sql: "kind IN ('nvd', 'kev', 'epss', 'usn', 'rhsa', 'msrc', 'wsusscn2', 'dsa')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_advisory_affects_ecosystem",
                table: "advisory_affects",
                sql: "ecosystem IN ('deb', 'rpm', 'windows')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_advisories_cvss_source",
                table: "advisories",
                sql: "cvss_source IS NULL OR cvss_source IN ('nvd', 'kev', 'epss', 'usn', 'rhsa', 'msrc', 'wsusscn2', 'dsa')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_advisories_source",
                table: "advisories",
                sql: "source IN ('nvd', 'usn', 'rhsa', 'msrc', 'dsa')");
        }
    }
}
