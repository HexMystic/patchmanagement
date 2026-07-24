using Npgsql;
using PatchManagement.Content.Abstractions;
using PatchManagement.Content.Model;

namespace PatchManagement.Content.Ingestion;

/// <summary>
/// Npgsql-based implementation of <see cref="IContentStore"/>. Uses raw parameterized SQL with
/// <c>ON CONFLICT</c> rather than EF, for two reasons: it targets the frozen unique keys exactly
/// (including the <c>NULLS NOT DISTINCT</c> arbiter on <c>advisory_affects</c>, which EF's
/// change-tracker cannot express as an upsert), and it keeps the ingestion path free of a
/// tenant-scoped <c>AppDbContext</c> the content role has no business loading (ADR 0010).
///
/// All values are passed as parameters — never string-concatenated — so a malformed feed cannot
/// inject SQL, and no credential could ever be interpolated into a statement (CLAUDE.md NEVER #1).
///
/// Provenance MERGE strategy (ON CONFLICT): keep every entry whose <c>source</c> the incoming
/// record does not carry, then append the incoming entries. Re-ingesting the same feed replaces
/// only its own provenance entry; an advisory enriched by NVD + KEV + EPSS keeps all three even as
/// NVD re-syncs.
/// </summary>
public sealed class ContentStore : IContentStore
{
    // Keep prior provenance entries whose source is NOT present in the incoming record, then append
    // the incoming array. `src` is the table alias the ON CONFLICT arbiter exposes for the row.
    private static string MergeProvenance(string tableAlias) => $@"
COALESCE(
    (SELECT jsonb_agg(e)
     FROM jsonb_array_elements({tableAlias}.provenance) e
     WHERE NOT (e->>'source' IN (
         SELECT p->>'source' FROM jsonb_array_elements(EXCLUDED.provenance) p))),
    '[]'::jsonb)
|| EXCLUDED.provenance";

    public async Task EnsureSourceAsync(
        NpgsqlConnection conn, string kind, string instance, string? endpoint, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO content_sources (id, kind, instance, endpoint, enabled, last_status, created_at, updated_at)
VALUES (gen_random_uuid(), @kind, @instance, @endpoint, true, 'never-run', now(), now())
ON CONFLICT (kind, instance) DO UPDATE
    SET endpoint = COALESCE(EXCLUDED.endpoint, content_sources.endpoint),
        updated_at = now();";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.Add(P("kind", kind));
        cmd.Parameters.Add(P("instance", instance));
        cmd.Parameters.Add(P("endpoint", endpoint));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<string?> GetCursorAsync(
        NpgsqlConnection conn, string kind, string instance, CancellationToken ct)
    {
        const string sql = "SELECT cursor FROM content_sources WHERE kind = @kind AND instance = @instance;";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.Add(P("kind", kind));
        cmd.Parameters.Add(P("instance", instance));
        var value = await cmd.ExecuteScalarAsync(ct);
        return value is null or DBNull ? null : (string)value;
    }

    public async Task UpdateSyncStatusAsync(
        NpgsqlConnection conn, string kind, string instance,
        string? cursor, string status, string? error, CancellationToken ct)
    {
        const string sql = @"
UPDATE content_sources
SET cursor = @cursor,
    last_sync_at = now(),
    last_status = @status,
    last_error = @error,
    updated_at = now()
WHERE kind = @kind AND instance = @instance;";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.Add(P("kind", kind));
        cmd.Parameters.Add(P("instance", instance));
        cmd.Parameters.Add(P("cursor", cursor));
        cmd.Parameters.Add(P("status", status));
        cmd.Parameters.Add(P("error", error));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<Guid> UpsertAdvisoryAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, NormalizedAdvisory a, CancellationToken ct)
    {
        // NOTE: this deliberately does NOT touch kev_* / epss_* — those columns are owned by the
        // overlay connectors (KEV, EPSS). A publisher re-sync must not wipe a previously applied
        // overlay back to "not evaluated".
        var sql = $@"
INSERT INTO advisories
    (id, source, external_id, title, severity, published_at, withdrawn_at,
     cvss_base_score, cvss_vector, cvss_version, cvss_source,
     provenance, source_metadata, raw_ref, created_at, updated_at)
VALUES
    (gen_random_uuid(), @source, @external_id, @title, @severity, @published_at, @withdrawn_at,
     @cvss_base_score, @cvss_vector, @cvss_version, @cvss_source,
     @provenance::jsonb, @source_metadata::jsonb, @raw_ref, now(), now())
ON CONFLICT (source, external_id) DO UPDATE SET
    title = EXCLUDED.title,
    severity = EXCLUDED.severity,
    published_at = EXCLUDED.published_at,
    withdrawn_at = EXCLUDED.withdrawn_at,
    cvss_base_score = EXCLUDED.cvss_base_score,
    cvss_vector = EXCLUDED.cvss_vector,
    cvss_version = EXCLUDED.cvss_version,
    cvss_source = EXCLUDED.cvss_source,
    source_metadata = EXCLUDED.source_metadata,
    raw_ref = EXCLUDED.raw_ref,
    provenance = ({MergeProvenance("advisories")}),
    updated_at = now()
RETURNING id;";

        await using var cmd = new NpgsqlCommand(sql, conn, tx);
        cmd.Parameters.Add(P("source", a.Source));
        cmd.Parameters.Add(P("external_id", a.ExternalId));
        cmd.Parameters.Add(P("title", a.Title));
        cmd.Parameters.Add(P("severity", a.Severity));
        cmd.Parameters.Add(P("published_at", a.PublishedAt));
        cmd.Parameters.Add(P("withdrawn_at", a.WithdrawnAt));
        cmd.Parameters.Add(P("cvss_base_score", a.CvssBaseScore));
        cmd.Parameters.Add(P("cvss_vector", a.CvssVector));
        cmd.Parameters.Add(P("cvss_version", a.CvssVersion));
        cmd.Parameters.Add(P("cvss_source", a.CvssSource));
        cmd.Parameters.Add(P("provenance", ProvenanceJson.Serialize(a.Provenance)));
        cmd.Parameters.Add(P("source_metadata", a.SourceMetadataJson));
        cmd.Parameters.Add(P("raw_ref", a.RawRef));
        var id = await cmd.ExecuteScalarAsync(ct);
        return (Guid)id!;
    }

    public async Task UpsertAffectAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, Guid advisoryId, NormalizedAffect af, CancellationToken ct)
    {
        // Arbiter is the UNIQUE NULLS NOT DISTINCT index (advisory_id, package_name, ecosystem,
        // platform). Inference by column list picks it up on PG16 (NULLS NOT DISTINCT since PG15).
        const string sql = @"
INSERT INTO advisory_affects
    (id, advisory_id, package_name, ecosystem, platform, fixed_version, backported, created_at)
VALUES
    (gen_random_uuid(), @advisory_id, @package_name, @ecosystem, @platform, @fixed_version, @backported, now())
ON CONFLICT (advisory_id, package_name, ecosystem, platform) DO UPDATE SET
    fixed_version = EXCLUDED.fixed_version,
    backported = EXCLUDED.backported;";

        await using var cmd = new NpgsqlCommand(sql, conn, tx);
        cmd.Parameters.Add(P("advisory_id", advisoryId));
        cmd.Parameters.Add(P("package_name", af.PackageName));
        cmd.Parameters.Add(P("ecosystem", af.Ecosystem));
        cmd.Parameters.Add(P("platform", af.Platform));
        cmd.Parameters.Add(P("fixed_version", af.FixedVersion));
        cmd.Parameters.Add(P("backported", af.Backported));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<Guid> UpsertPatchAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, NormalizedPatch p, CancellationToken ct)
    {
        var sql = $@"
INSERT INTO patches
    (id, source, vendor_id, title, reversible, requires_reboot, classification,
     published_at, withdrawn_at, provenance, source_metadata, created_at, updated_at)
VALUES
    (gen_random_uuid(), @source, @vendor_id, @title, @reversible, @requires_reboot, @classification,
     @published_at, @withdrawn_at, @provenance::jsonb, @source_metadata::jsonb, now(), now())
ON CONFLICT (source, vendor_id) DO UPDATE SET
    title = EXCLUDED.title,
    reversible = EXCLUDED.reversible,
    requires_reboot = EXCLUDED.requires_reboot,
    classification = EXCLUDED.classification,
    published_at = EXCLUDED.published_at,
    withdrawn_at = EXCLUDED.withdrawn_at,
    source_metadata = EXCLUDED.source_metadata,
    provenance = ({MergeProvenance("patches")}),
    updated_at = now()
RETURNING id;";

        await using var cmd = new NpgsqlCommand(sql, conn, tx);
        cmd.Parameters.Add(P("source", p.Source));
        cmd.Parameters.Add(P("vendor_id", p.VendorId));
        cmd.Parameters.Add(P("title", p.Title));
        cmd.Parameters.Add(P("reversible", p.Reversible));
        cmd.Parameters.Add(P("requires_reboot", p.RequiresReboot));
        cmd.Parameters.Add(P("classification", p.Classification));
        cmd.Parameters.Add(P("published_at", p.PublishedAt));
        cmd.Parameters.Add(P("withdrawn_at", p.WithdrawnAt));
        cmd.Parameters.Add(P("provenance", ProvenanceJson.Serialize(p.Provenance)));
        cmd.Parameters.Add(P("source_metadata", p.SourceMetadataJson));
        var id = await cmd.ExecuteScalarAsync(ct);
        return (Guid)id!;
    }

    public async Task<int> UpsertSupersedenceAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx,
        string source, string newerVendorId, string supersededVendorId, CancellationToken ct)
    {
        // The edge points from the OLDER (superseded) patch to the NEWER one. Both must already be
        // ingested; if the older one is not present yet the join yields nothing and no edge forms
        // (it forms on a later pass once both exist). The self-loop guard mirrors the DB CHECK.
        const string sql = @"
INSERT INTO patch_supersedence (patch_id, superseded_by_patch_id, created_at)
SELECT older.id, newer.id, now()
FROM patches newer
JOIN patches older ON older.source = newer.source AND older.vendor_id = @superseded
WHERE newer.source = @source AND newer.vendor_id = @newer AND older.id <> newer.id
ON CONFLICT (patch_id, superseded_by_patch_id) DO NOTHING;";

        await using var cmd = new NpgsqlCommand(sql, conn, tx);
        cmd.Parameters.Add(P("source", source));
        cmd.Parameters.Add(P("newer", newerVendorId));
        cmd.Parameters.Add(P("superseded", supersededVendorId));
        return await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<int> ApplyKevAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, KevOverlay k, CancellationToken ct)
    {
        // Overlay: enrich EVERY advisory carrying this CVE (a CVE may exist under nvd AND msrc AND
        // rhsa). Replace only the 'kev' provenance entry so re-running is idempotent.
        const string sql = @"
UPDATE advisories SET
    kev_listed = true,
    kev_date_added = @date_added,
    kev_due_date = @due_date,
    kev_known_ransomware_use = @ransom,
    provenance = COALESCE(
        (SELECT jsonb_agg(e) FROM jsonb_array_elements(provenance) e WHERE e->>'source' <> 'kev'),
        '[]'::jsonb) || @entry::jsonb,
    updated_at = now()
WHERE external_id = @cve;";

        await using var cmd = new NpgsqlCommand(sql, conn, tx);
        cmd.Parameters.Add(P("cve", k.CveId));
        cmd.Parameters.Add(P("date_added", k.DateAdded));
        cmd.Parameters.Add(P("due_date", k.DueDate));
        cmd.Parameters.Add(P("ransom", k.KnownRansomwareUse));
        cmd.Parameters.Add(P("entry", ProvenanceJson.SerializeOne(k.Provenance)));
        return await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<int> ApplyEpssAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, EpssOverlay e, CancellationToken ct)
    {
        const string sql = @"
UPDATE advisories SET
    epss_score = @score,
    epss_percentile = @percentile,
    epss_scored_at = @scored_at,
    provenance = COALESCE(
        (SELECT jsonb_agg(x) FROM jsonb_array_elements(provenance) x WHERE x->>'source' <> 'epss'),
        '[]'::jsonb) || @entry::jsonb,
    updated_at = now()
WHERE external_id = @cve;";

        await using var cmd = new NpgsqlCommand(sql, conn, tx);
        cmd.Parameters.Add(P("cve", e.CveId));
        cmd.Parameters.Add(P("score", e.Score));
        cmd.Parameters.Add(P("percentile", e.Percentile));
        cmd.Parameters.Add(P("scored_at", e.ScoredAt));
        cmd.Parameters.Add(P("entry", ProvenanceJson.SerializeOne(e.Provenance)));
        return await cmd.ExecuteNonQueryAsync(ct);
    }

    private static NpgsqlParameter P(string name, object? value) =>
        new(name, value ?? DBNull.Value);
}
