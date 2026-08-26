using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using PatchManagement.Contracts.States;
using PatchManagement.Persistence.Entities;

namespace PatchManagement.Persistence;

/// <summary>
/// The application DbContext.
///
/// TENANCY: every entity is tenant-scoped (<c>tenant_id</c> + RLS, policies and FORCE applied in
/// the migration SQL) EXCEPT two groups:
/// <list type="bullet">
///   <item><see cref="Tenant"/> — the root registry.</item>
///   <item>The <b>global content catalogue</b> — <see cref="ContentSource"/>,
///   <see cref="Advisory"/>, <see cref="AdvisoryAffects"/>, <see cref="Patch"/>,
///   <see cref="PatchSupersedence"/> — public vendor content that is identical for every tenant
///   (CLAUDE.md §4.1 exemption, ADR 0010). Read-only to <c>patchmgmt_app</c>, written by
///   <c>patchmgmt_content</c>. The exemption is asserted by <c>RlsConventionTests</c>.</item>
/// </list>
///
/// Column names are snake_cased by convention (configured in <c>AddPersistence</c> and the
/// design-time factory).
/// </summary>
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    /// <summary>
    /// Every feed we ingest. Valid for <c>content_sources.kind</c>, for <c>cvss_source</c> (which
    /// records which feed SUPPLIED a score — provenance semantics, so the full feed list is
    /// correct, not the narrower publisher list), and for provenance entries — KEV and EPSS ARE
    /// legitimate provenance, they are just not advisory/patch publishers.
    /// <c>dsa</c> = Debian Security Advisory: required by HARD-PROBLEMS #2/#3 and by the Debian 12
    /// member of the lab fleet.
    /// </summary>
    /// <para><c>vendor</c> (ADR 0019) is the GENERIC third-party application feed kind. It is
    /// deliberately not per-vendor: <c>content_sources.instance</c> already separates one feed from
    /// the next (UNIQUE (kind, instance)), so 'google-chrome' and 'adobe-reader' are instances of
    /// kind 'vendor', never kinds of their own. Widening this list also widens
    /// <c>ck_advisories_cvss_source</c> below, which reads it — intentional: a vendor advisory that
    /// carries its own CVSS score must be able to say so.</para>
    private static readonly string[] ContentSourceKinds =
        ["nvd", "kev", "epss", "usn", "rhsa", "msrc", "wsusscn2", "dsa", "vendor"];

    /// <summary>
    /// Sources that PUBLISH advisories. Excludes kev/epss (scoring overlays that enrich an
    /// existing advisory) and wsusscn2 (an applicability catalogue of updates, i.e. patches —
    /// ADR 0008 pairs it with MSRC CSAF, which is the advisory side).
    /// Includes <c>dsa</c>: Debian is an independent distro (no USN/RHSA covers it), so without it
    /// a Debian advisory has no representable source and Phase 5 would hit this CHECK on first
    /// ingest against the lab's Debian 12 box. Rocky/Alma are RHEL rebuilds assessed via
    /// <c>rhsa</c> (see phase-1.md); native RLSA/ALSA is a deferred Phase-5/6 precision decision.
    /// </summary>
    /// <para>Includes <c>vendor</c> (ADR 0019): a third-party application vendor publishing its own
    /// advisory. Generic by design — see <see cref="ContentSourceKinds"/>. Phase 16 must namespace
    /// <c>external_id</c> per vendor, because UNIQUE (source, external_id) no longer gets vendor
    /// separation for free once every vendor shares one source value.</para>
    private static readonly string[] AdvisorySources = ["nvd", "usn", "rhsa", "msrc", "dsa", "vendor"];

    /// <summary>
    /// Sources that publish installable updates. NVD describes vulnerabilities, not fixes.
    /// <c>dsa</c> mirrors <c>usn</c>: a Debian fix, like an Ubuntu one, is "upgrade to the stated
    /// package version", so if Phase 5 models USN updates as patches it models DSA the same way —
    /// permitting the value here avoids a day-one amend.
    /// </summary>
    /// <para><c>vendor</c> (ADR 0019) covers a third-party application installer — an MSI, EXE, PKG
    /// or DMG the vendor ships. Same namespacing caveat as <see cref="AdvisorySources"/>: UNIQUE
    /// (source, vendor_id) means Phase 16 qualifies <c>vendor_id</c> per vendor.</para>
    private static readonly string[] PatchSources = ["usn", "rhsa", "msrc", "wsusscn2", "dsa", "vendor"];

    /// <summary>
    /// NOT NULL on a jsonb column still accepts '[]', and an empty provenance array is an
    /// unattributable score — precisely what DIFFERENTIATORS #4 forbids. JSON-schema validation
    /// cannot cover this: Phase 5 writes through EF, not through the validator.
    /// </summary>
    private static string NonEmptyJsonArray(string column) =>
        $"jsonb_typeof({column}) = 'array' AND jsonb_array_length({column}) >= 1";

    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<Operator> Operators => Set<Operator>();
    public DbSet<Credential> Credentials => Set<Credential>();
    public DbSet<DataKey> DataKeys => Set<DataKey>();
    public DbSet<AuditLogEntry> AuditLog => Set<AuditLogEntry>();
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<AssetPackage> AssetPackages => Set<AssetPackage>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<DiscoveryRun> DiscoveryRuns => Set<DiscoveryRun>();
    public DbSet<AssetEvidence> AssetEvidence => Set<AssetEvidence>();
    public DbSet<HostKey> HostKeys => Set<HostKey>();

    // Global content catalogue (no tenant_id, no RLS) — see the class summary and ADR 0010.
    public DbSet<ContentSource> ContentSources => Set<ContentSource>();
    public DbSet<Advisory> Advisories => Set<Advisory>();
    public DbSet<AdvisoryAffects> AdvisoryAffects => Set<AdvisoryAffects>();
    public DbSet<Patch> Patches => Set<Patch>();
    public DbSet<PatchSupersedence> PatchSupersedence => Set<PatchSupersedence>();

    private static string InList(string column, IEnumerable<string> values) =>
        $"{column} IN ({string.Join(", ", values.Select(v => $"'{v}'"))})";

    protected override void OnModelCreating(ModelBuilder b)
    {
        var stateConverter = new ValueConverter<EndpointState, string>(
            v => v.ToDbValue(),
            v => EndpointStateNames.FromDbValue(v));

        b.Entity<Tenant>(e =>
        {
            e.ToTable("tenants");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).IsRequired();
            e.Property(x => x.Status).IsRequired();
        });

        b.Entity<Operator>(e =>
        {
            e.ToTable("operators");
            e.HasKey(x => x.Id);
            e.Property(x => x.Email).IsRequired();
            e.HasIndex(x => new { x.TenantId, x.Email }).IsUnique();
            TenantFk(e);
        });

        b.Entity<Credential>(e =>
        {
            e.ToTable("credentials");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).IsRequired();
            e.Property(x => x.Kind).HasConversion<string>();
            TenantFk(e);

            // Tenant-consistent: a credential can only reference a DEK of its OWN tenant.
            // Optional (DataKeyId is nullable until Phase 2 seals the envelope); PostgreSQL's
            // default MATCH SIMPLE skips the check while data_key_id is NULL.
            e.HasOne<DataKey>()
                .WithMany()
                .HasPrincipalKey(x => new { x.TenantId, x.Id })
                .HasForeignKey(x => new { x.TenantId, x.DataKeyId })
                .OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<DataKey>(e =>
        {
            e.ToTable("data_keys");
            e.HasKey(x => x.Id);
            // Target for the tenant-consistent FK from credentials.
            e.HasAlternateKey(x => new { x.TenantId, x.Id });
            TenantFk(e);
        });

        b.Entity<AuditLogEntry>(e =>
        {
            e.ToTable("audit_log");
            e.HasKey(x => x.Id);
            e.Property(x => x.Actor).IsRequired();
            e.Property(x => x.Action).IsRequired();
            e.Property(x => x.Target).IsRequired();
            e.Property(x => x.Detail).HasColumnType("jsonb");
            e.HasIndex(x => new { x.TenantId, x.At });

            // CORRECT UNTIL M4: blocks auditing an action attempted against a nonexistent tenant.
            // Added because phantom-tenant writes are the larger risk today (review H3 + H1).
            // M4 (system-scope audit for Phase 2's cross-tenant KEK rotation) will make TenantId
            // nullable — a nullable FK stays compatible, so this needs no redesign then, but
            // Phase 2 must not treat it as settled. See ADR 0010 and ROADMAP.
            TenantFk(e);
        });

        b.Entity<Asset>(e =>
        {
            e.ToTable("assets", t =>
                // Review M8: the source vocabulary was documented in three places and enforced in
                // none, so any raw-SQL or non-.NET writer could put an unknown value here. It also
                // silently underpins ux_assets_discovery_candidate below, whose predicate matches
                // the literal 'discovery' — a typo'd or retired value would make that index match
                // nothing and the natural key stop keying, with nothing failing.
                t.HasCheckConstraint("ck_assets_source", InList("source", AssetSources.All)));
            e.HasKey(x => x.Id);
            // Target for the tenant-consistent FKs from asset_packages and findings.
            e.HasAlternateKey(x => new { x.TenantId, x.Id });
            e.Property(x => x.Hostname).IsRequired();
            e.Property(x => x.Source).IsRequired();
            e.Property(x => x.State).HasConversion(stateConverter).IsRequired();
            e.HasIndex(x => new { x.TenantId, x.Hostname });

            // The discovery natural key (ADR 0024). PARTIAL, and that is the point: a sweep observes
            // a reachability coordinate, not a machine identity — it cannot read a machine id without
            // logging in — so this key is valid only for the pre-identity state and stops being the
            // arbiter once inventory establishes one. Keyed on ip AND port because the five lab
            // containers share 127.0.0.1; without the port they collapse into one asset.
            e.HasIndex(x => new { x.TenantId, x.Ip, x.EndpointPort })
                .HasDatabaseName("ux_assets_discovery_candidate")
                .IsUnique()
                .HasFilter("source = 'discovery' AND ip IS NOT NULL AND endpoint_port IS NOT NULL");

            TenantFk(e);
        });

        b.Entity<AssetPackage>(e =>
        {
            e.ToTable("asset_packages");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).IsRequired();
            e.Property(x => x.Version).IsRequired();
            e.HasIndex(x => new { x.TenantId, x.AssetId });
            TenantFk(e);

            // Inventory belongs to its asset: removing the asset removes its packages.
            e.HasOne<Asset>()
                .WithMany()
                .HasPrincipalKey(x => new { x.TenantId, x.Id })
                .HasForeignKey(x => new { x.TenantId, x.AssetId })
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<Finding>(e =>
        {
            e.ToTable("findings");
            e.HasKey(x => x.Id);
            e.Property(x => x.State).HasConversion(stateConverter).IsRequired();
            e.Property(x => x.RiskExplanation).HasColumnType("jsonb");
            e.HasIndex(x => new { x.TenantId, x.AssetId });
            e.HasIndex(x => new { x.TenantId, x.State });
            TenantFk(e);

            // Tenant-consistent (review H3 failure 1): RLS stops you READING another tenant's
            // asset, but only this composite FK stops you WRITING a finding that references one.
            // Restrict, not Cascade: findings are evidence — deleting an asset must not silently
            // erase its history.
            e.HasOne<Asset>()
                .WithMany()
                .HasPrincipalKey(x => new { x.TenantId, x.Id })
                .HasForeignKey(x => new { x.TenantId, x.AssetId })
                .OnDelete(DeleteBehavior.Restrict);

            // Content is GLOBAL, so these are plain single-column FKs — there is no tenant
            // component to keep consistent (ADR 0010). Restrict: content retires via
            // withdrawn_at, and a finding must never outlive the content that explains it.
            e.HasOne<Advisory>()
                .WithMany()
                .HasForeignKey(x => x.AdvisoryId)
                .OnDelete(DeleteBehavior.Restrict);

            e.HasOne<Patch>()
                .WithMany()
                .HasForeignKey(x => x.PatchId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<DiscoveryRun>(e =>
        {
            e.ToTable("discovery_runs", t =>
            {
                t.HasCheckConstraint(
                    "ck_discovery_runs_outcome", InList("outcome", DiscoveryRunOutcomes.All));

                // A refused sweep probed nothing. Enforced rather than trusted, because "refused"
                // and "found nothing" being indistinguishable is the defect this phase keeps
                // designing against — Phase 5 shipped it three times as an empty batch with a green
                // status and an advanced cursor.
                t.HasCheckConstraint(
                    "ck_discovery_runs_refusal_probed_nothing",
                    "outcome NOT IN ('refused-by-policy', 'invalid-range') OR addresses_probed = 0");

                // Open exactly while it has no completion time.
                t.HasCheckConstraint(
                    "ck_discovery_runs_completion",
                    "(outcome = 'running') = (completed_at IS NULL)");
            });

            e.HasKey(x => x.Id);
            // Target for the tenant-consistent FK from asset_evidence.
            e.HasAlternateKey(x => new { x.TenantId, x.Id });
            e.Property(x => x.Outcome).IsRequired();
            e.Property(x => x.RequestedRanges).HasColumnType("jsonb").IsRequired();
            e.Property(x => x.RequestedPorts).HasColumnType("jsonb").IsRequired();
            e.Property(x => x.RefusedRanges).HasColumnType("jsonb").IsRequired();
            e.HasIndex(x => new { x.TenantId, x.StartedAt });
            TenantFk(e);
        });

        b.Entity<AssetEvidence>(e =>
        {
            e.ToTable("asset_evidence", t =>
            {
                t.HasCheckConstraint(
                    "ck_asset_evidence_source", InList("source", AssetSources.All));

                // Discovery evidence with no run is not provenance, and every other source has no
                // run to name.
                t.HasCheckConstraint(
                    "ck_asset_evidence_discovery_names_its_run",
                    "(source = 'discovery') = (discovery_run_id IS NOT NULL)");
            });

            e.HasKey(x => x.Id);
            e.Property(x => x.Source).IsRequired();
            e.Property(x => x.Detail).HasColumnType("jsonb");
            e.HasIndex(x => new { x.TenantId, x.AssetId });
            e.HasIndex(x => new { x.TenantId, x.Source, x.Present });
            TenantFk(e);

            // Restrict, not Cascade — the departure from asset_packages is deliberate. This row is
            // WHY an asset is flagged what it is flagged (CLAUDE.md §4.6); letting a delete erase it
            // would make the flag retroactively unexplainable.
            e.HasOne<Asset>()
                .WithMany()
                .HasPrincipalKey(x => new { x.TenantId, x.Id })
                .HasForeignKey(x => new { x.TenantId, x.AssetId })
                .OnDelete(DeleteBehavior.Restrict);

            e.HasOne<DiscoveryRun>()
                .WithMany()
                .HasPrincipalKey(x => new { x.TenantId, x.Id })
                .HasForeignKey(x => new { x.TenantId, x.DiscoveryRunId })
                .OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<HostKey>(e =>
        {
            e.ToTable("host_keys", t =>
            {
                t.HasCheckConstraint("ck_host_keys_status", InList("status", HostKeyStatuses.All));
                t.HasCheckConstraint("ck_host_keys_port", "port BETWEEN 1 AND 65535");
                t.HasCheckConstraint(
                    "ck_host_keys_superseded_at",
                    $"(status IN ({string.Join(", ", HostKeyStatuses.Closed.Select(v => $"'{v}'"))}))"
                    + " = (superseded_at IS NOT NULL)");
                t.HasCheckConstraint(
                    "ck_host_keys_verified_after_first_seen", "last_verified_at >= first_seen_at");
            });

            e.HasKey(x => x.Id);
            e.Property(x => x.Host).IsRequired();
            e.Property(x => x.KeyAlgorithm).IsRequired();
            e.Property(x => x.FingerprintSha256).IsRequired();
            e.Property(x => x.PublicKey).IsRequired();
            e.Property(x => x.Status).IsRequired();

            // THE PIN: at most one trusted key per endpoint, so "which key do we trust" has exactly
            // one answer and a changed key must supersede rather than accumulate alongside.
            e.HasIndex(x => new { x.TenantId, x.Host, x.Port })
                .HasDatabaseName("ux_host_keys_trusted_endpoint")
                .IsUnique()
                .HasFilter("status = 'trusted'");

            e.HasIndex(x => new { x.TenantId, x.FingerprintSha256 });
            e.HasIndex(x => new { x.TenantId, x.AssetId });
            TenantFk(e);

            e.HasOne<Asset>()
                .WithMany()
                .HasPrincipalKey(x => new { x.TenantId, x.Id })
                .HasForeignKey(x => new { x.TenantId, x.AssetId })
                .OnDelete(DeleteBehavior.Restrict);
        });

        ConfigureContentCatalogue(b);
    }

    /// <summary>
    /// Every tenant-scoped table references <c>tenants(id)</c>. Without this, an unauthenticated
    /// caller can invent a GUID, send it as <c>X-Tenant-Id</c>, and insert rows "belonging" to a
    /// tenant that does not exist — RLS's WITH CHECK passes because the GUC matches the row
    /// (review H3 failure 2). Restrict: a tenant with data cannot be silently deleted out from
    /// under it.
    /// </summary>
    private static void TenantFk<T>(EntityTypeBuilder<T> e) where T : class =>
        e.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey("TenantId")
            .OnDelete(DeleteBehavior.Restrict);

    /// <summary>
    /// The GLOBAL content catalogue — no <c>tenant_id</c>, no RLS (CLAUDE.md §4.1 exemption,
    /// ADR 0010). Grants, the <c>patchmgmt_content</c> role, and the absence of RLS are applied in
    /// the migration SQL and asserted by <c>RlsConventionTests</c>.
    ///
    /// Every unique key here is an <b>idempotency key</b>: Phase 5's refresh is incremental and
    /// retried (HARD-PROBLEMS #6), so each upsert needs something to conflict against
    /// (review M9). CHECK constraints pin the enum vocabularies at the database, not just in C#
    /// (review M8).
    /// </summary>
    private static void ConfigureContentCatalogue(ModelBuilder b)
    {
        b.Entity<ContentSource>(e =>
        {
            e.ToTable("content_sources", t =>
            {
                t.HasCheckConstraint("ck_content_sources_kind", InList("kind", ContentSourceKinds));
                t.HasCheckConstraint(
                    "ck_content_sources_last_status",
                    InList("last_status", ["ok", "failed", "never-run"]));
            });
            e.HasKey(x => x.Id);
            e.Property(x => x.Kind).IsRequired();
            e.Property(x => x.Instance).IsRequired();
            e.Property(x => x.LastStatus).IsRequired();

            // (kind, instance), NOT kind alone: one feed per stream, because RHSA/USN/DSA are
            // published per release. Keying on kind would cap the deployment at 7 feeds forever.
            e.HasIndex(x => new { x.Kind, x.Instance }).IsUnique();
        });

        b.Entity<Advisory>(e =>
        {
            e.ToTable("advisories", t =>
            {
                t.HasCheckConstraint("ck_advisories_source", InList("source", AdvisorySources));
                t.HasCheckConstraint(
                    "ck_advisories_severity",
                    InList("severity", ["none", "low", "medium", "high", "critical", "unknown"]));
                t.HasCheckConstraint(
                    "ck_advisories_provenance_non_empty", NonEmptyJsonArray("provenance"));
                t.HasCheckConstraint(
                    "ck_advisories_cvss_source",
                    $"cvss_source IS NULL OR {InList("cvss_source", ContentSourceKinds)}");
                t.HasCheckConstraint(
                    "ck_advisories_cvss_version",
                    "cvss_version IS NULL OR cvss_version IN ('2.0', '3.0', '3.1', '4.0')");
                t.HasCheckConstraint(
                    "ck_advisories_cvss_base_score",
                    "cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)");
                // EPSS values are probabilities in [0,1], not percentages — a 0-100 value here
                // would silently inflate every Phase 7 risk score that consumes it.
                t.HasCheckConstraint(
                    "ck_advisories_epss_score",
                    "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)");
                t.HasCheckConstraint(
                    "ck_advisories_epss_percentile",
                    "epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)");
            });
            e.HasKey(x => x.Id);
            e.Property(x => x.Source).IsRequired();
            e.Property(x => x.ExternalId).IsRequired();
            e.Property(x => x.Title).IsRequired();
            e.Property(x => x.Severity).IsRequired();
            e.Property(x => x.Provenance).HasColumnType("jsonb").IsRequired();
            e.Property(x => x.SourceMetadata).HasColumnType("jsonb");
            e.HasIndex(x => new { x.Source, x.ExternalId }).IsUnique(); // the upsert key
        });

        b.Entity<AdvisoryAffects>(e =>
        {
            e.ToTable("advisory_affects", t =>
                t.HasCheckConstraint(
                    "ck_advisory_affects_ecosystem",
                    // 'app' (ADR 0019) is the generic fourth ecosystem: a third-party application
                    // installer is not a dpkg package, not an rpm, and not a Windows build
                    // threshold, so without it a third-party fix statement has no representable
                    // row. The vendor's name belongs in package_name, never here.
                    InList("ecosystem", ["deb", "rpm", "windows", "app"])));
            e.HasKey(x => x.Id);
            e.Property(x => x.PackageName).IsRequired();
            e.Property(x => x.Ecosystem).IsRequired();

            e.HasOne(x => x.Advisory)
                .WithMany()
                .HasForeignKey(x => x.AdvisoryId)
                .OnDelete(DeleteBehavior.Cascade);

            // ROW GRAIN — platform is part of the identity, because one advisory routinely fixes
            // the same package at different versions per release (one USN covers every supported
            // Ubuntu release). Keying without it would REJECT those legitimate rows.
            //
            // AreNullsDistinct(false) => UNIQUE NULLS NOT DISTINCT. Load-bearing: platform is NULL
            // whenever a source states no release scope (NVD CPE ranges), and under PostgreSQL's
            // default NULL-distinct semantics two such rows would BOTH insert, silently breaking
            // the idempotent upsert exactly where Phase 5 needs it (ADR 0011, review M9).
            e.HasIndex(x => new { x.AdvisoryId, x.PackageName, x.Ecosystem, x.Platform })
                .IsUnique()
                .AreNullsDistinct(false);

            // Phase 6 correlates inventory -> content by (package, ecosystem).
            e.HasIndex(x => new { x.PackageName, x.Ecosystem });
        });

        b.Entity<Patch>(e =>
        {
            e.ToTable("patches", t =>
            {
                t.HasCheckConstraint("ck_patches_source", InList("source", PatchSources));
                t.HasCheckConstraint(
                    "ck_patches_provenance_non_empty", NonEmptyJsonArray("provenance"));
            });
            e.HasKey(x => x.Id);
            e.Property(x => x.Source).IsRequired();
            e.Property(x => x.VendorId).IsRequired();
            e.Property(x => x.Title).IsRequired();
            e.Property(x => x.Provenance).HasColumnType("jsonb").IsRequired();
            e.Property(x => x.SourceMetadata).HasColumnType("jsonb");
            e.HasIndex(x => new { x.Source, x.VendorId }).IsUnique(); // the upsert key
        });

        b.Entity<PatchSupersedence>(e =>
        {
            e.ToTable("patch_supersedence", t =>
                // Self-loops are always wrong and cheap to reject here. DEEPER cycles need the
                // whole graph, so Phase 6's traversal detects and breaks those (HARD-PROBLEMS #4).
                t.HasCheckConstraint(
                    "ck_patch_supersedence_no_self_loop",
                    "patch_id <> superseded_by_patch_id"));

            // The edge itself is the key: re-ingesting it is a no-op upsert, not a duplicate.
            e.HasKey(x => new { x.PatchId, x.SupersededByPatchId });

            e.HasOne(x => x.Patch)
                .WithMany()
                .HasForeignKey(x => x.PatchId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(x => x.SupersededByPatch)
                .WithMany()
                .HasForeignKey(x => x.SupersededByPatchId)
                .OnDelete(DeleteBehavior.Cascade);

            // Reverse traversal: "what does this patch supersede?" walks toward the effective head.
            e.HasIndex(x => x.SupersededByPatchId);
        });
    }
}
