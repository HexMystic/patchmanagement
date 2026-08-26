using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PatchManagement.Persistence.Migrations
{
    /// <summary>
    /// Constrains <c>assets.source</c> to its documented vocabulary — an ADDENDUM to ADR 0024, not
    /// a new decision: the natural key that ADR turned on has a predicate matching the literal
    /// <c>'discovery'</c>, so the key and the vocabulary are one contract.
    ///
    /// WHAT THIS FIXES. <c>ux_assets_discovery_candidate</c> is
    /// <c>WHERE source = 'discovery' AND ...</c>. If that value were ever typo'd, renamed or
    /// retired, the partial index would match no rows, the discovery upsert would stop having
    /// anything to conflict against, and NOTHING would fail — duplicate candidates would simply
    /// start accumulating. The dependency was documented; now it is enforced.
    ///
    /// ALL FOUR VALUES, NOT JUST THE ONE IN USE. A codebase-wide sweep of every writer found
    /// exactly one value ever written: 'discovery' (the entity default, two test constructions and
    /// two raw-SQL inserts in ContentCatalogueTests). 'ad', 'dhcp' and 'inventory' are what slice
    /// 4's correlation will write. A CHECK admitting only what exists today would turn the next
    /// legitimate write into a 23514 at the moment correlation first runs.
    ///
    /// SAFE TO APPLY: assets is 0 rows, verified before writing this. On a populated database this
    /// migration fails loudly if any row holds an unlisted value, which is the correct direction.
    ///
    /// Closes the <c>assets.source</c> part of review M8 (five enum-shaped columns typed as
    /// unconstrained text). The other four — assets.state, findings.state, credentials.kind,
    /// tenants.status — remain open and are not Phase 4's to close.
    /// </summary>
    public partial class AssetSourceVocabulary : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddCheckConstraint(
                name: "ck_assets_source",
                table: "assets",
                sql: "source IN ('discovery', 'ad', 'dhcp', 'inventory')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_assets_source",
                table: "assets");
        }
    }
}
