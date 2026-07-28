using Npgsql;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Abstractions;

/// <summary>
/// The idempotent upsert engine for the global content catalogue. Every write is an UPSERT against
/// a frozen unique key, so an incremental refresh that re-sees a record updates it in place rather
/// than duplicating (HARD-PROBLEMS #6, review M9):
/// <list type="bullet">
///   <item>advisories — <c>(source, external_id)</c></item>
///   <item>patches — <c>(source, vendor_id)</c></item>
///   <item>advisory_affects — <c>(advisory_id, package_name, ecosystem, platform)</c> NULLS NOT DISTINCT</item>
///   <item>patch_supersedence — PK <c>(patch_id, superseded_by_patch_id)</c></item>
///   <item>content_sources — <c>(kind, instance)</c></item>
/// </list>
/// All methods run on a caller-supplied <see cref="NpgsqlConnection"/> opened as the
/// <c>patchmgmt_content</c> role (SELECT/INSERT/UPDATE, no DELETE — content retires via
/// <c>withdrawn_at</c>, ADR 0010) and, for the mutating catalogue writes, inside the caller's
/// transaction so one feed sync is atomic. Provenance merges are additive-by-source: re-ingesting
/// replaces that source's own entry and preserves entries other feeds contributed.
/// </summary>
public interface IContentStore
{
    /// <summary>Insert the feed row if absent (idempotent on <c>(kind, instance)</c>); update its endpoint.</summary>
    Task EnsureSourceAsync(
        NpgsqlConnection conn, string kind, string instance, string? endpoint, CancellationToken ct);

    /// <summary>Read the persisted incremental cursor for a feed, or null if never synced.</summary>
    Task<string?> GetCursorAsync(NpgsqlConnection conn, string kind, string instance, CancellationToken ct);

    /// <summary>Record the honest sync outcome: cursor, <c>last_sync_at</c>, <c>last_status</c>, <c>last_error</c>.</summary>
    Task UpdateSyncStatusAsync(
        NpgsqlConnection conn, string kind, string instance,
        string? cursor, string status, string? error, CancellationToken ct);

    /// <summary>Upsert an advisory on <c>(source, external_id)</c>; returns its id.</summary>
    Task<Guid> UpsertAdvisoryAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, NormalizedAdvisory advisory, CancellationToken ct);

    /// <summary>Upsert one fix statement on <c>(advisory_id, package_name, ecosystem, platform)</c>.</summary>
    Task UpsertAffectAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, Guid advisoryId, NormalizedAffect affect, CancellationToken ct);

    /// <summary>Upsert a patch on <c>(source, vendor_id)</c>; returns its id.</summary>
    Task<Guid> UpsertPatchAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, NormalizedPatch patch, CancellationToken ct);

    /// <summary>
    /// Upsert a supersedence edge: <paramref name="supersededVendorId"/> is superseded BY
    /// <paramref name="newerVendorId"/>, both resolved within <paramref name="source"/>. Returns the
    /// number of edges written (0 if the older patch is not yet ingested, or on ON CONFLICT DO NOTHING).
    /// </summary>
    Task<int> UpsertSupersedenceAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx,
        string source, string newerVendorId, string supersededVendorId, CancellationToken ct);

    /// <summary>Apply a KEV overlay to every advisory whose <c>external_id</c> matches the CVE. Returns rows enriched.</summary>
    Task<int> ApplyKevAsync(NpgsqlConnection conn, NpgsqlTransaction tx, KevOverlay overlay, CancellationToken ct);

    /// <summary>Apply an EPSS overlay to every advisory whose <c>external_id</c> matches the CVE. Returns rows enriched.</summary>
    Task<int> ApplyEpssAsync(NpgsqlConnection conn, NpgsqlTransaction tx, EpssOverlay overlay, CancellationToken ct);
}
