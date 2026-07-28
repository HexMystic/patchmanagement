using Microsoft.Extensions.Logging;
using Npgsql;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Ingestion;

/// <summary>
/// Orchestrates one feed sync end to end: ensure the <c>content_sources</c> row exists, hand the
/// connector its incremental cursor, persist the normalized batch atomically, and record an HONEST
/// outcome on <c>content_sources</c> (ok/failed + cursor + counts) — so a stale catalogue can never
/// masquerade as current and a partial write can never be half-committed (HARD-PROBLEMS #6/#8).
///
/// The whole catalogue write runs in a single transaction, so a feed either fully applies or not at
/// all. The cursor only advances on success, which makes a failed-then-retried run resume rather
/// than skip. Patches are upserted BEFORE their supersedence edges so edge resolution finds both
/// endpoints (HARD-PROBLEMS #4).
/// </summary>
public sealed class ContentSyncService(
    IContentStore store,
    IContentConnectionFactory connections,
    ILogger<ContentSyncService> logger)
{
    public async Task<SyncOutcome> RunAsync(
        IContentConnector connector, string instance, string? endpoint, CancellationToken ct)
    {
        await using var conn = await connections.OpenAsync(ct);

        await store.EnsureSourceAsync(conn, connector.Kind, instance, endpoint, ct);
        var cursor = await store.GetCursorAsync(conn, connector.Kind, instance, ct);
        var state = new ContentSourceState(instance, endpoint, cursor);

        try
        {
            var batch = await connector.SyncAsync(state, ct);

            int advisories = 0, affects = 0, patches = 0, edges = 0, overlays = 0;

            await using (var tx = await conn.BeginTransactionAsync(ct))
            {
                foreach (var advisory in batch.Advisories)
                {
                    var advisoryId = await store.UpsertAdvisoryAsync(conn, tx, advisory, ct);
                    advisories++;
                    foreach (var affect in advisory.Affects)
                    {
                        await store.UpsertAffectAsync(conn, tx, advisoryId, affect, ct);
                        affects++;
                    }
                }

                // Two passes: all patches, THEN edges — so a supersedence edge can resolve both of
                // its endpoints even when the superseded patch appears later in the same batch.
                foreach (var patch in batch.Patches)
                {
                    await store.UpsertPatchAsync(conn, tx, patch, ct);
                    patches++;
                }

                foreach (var patch in batch.Patches)
                foreach (var superseded in patch.Supersedes)
                    edges += await store.UpsertSupersedenceAsync(
                        conn, tx, patch.Source, patch.VendorId, superseded, ct);

                foreach (var kev in batch.KevOverlays)
                    overlays += await store.ApplyKevAsync(conn, tx, kev, ct);

                foreach (var epss in batch.EpssOverlays)
                    overlays += await store.ApplyEpssAsync(conn, tx, epss, ct);

                await tx.CommitAsync(ct);
            }

            await store.UpdateSyncStatusAsync(
                conn, connector.Kind, instance, batch.Cursor, SyncOutcome.Ok, error: null, ct);

            logger.LogInformation(
                "Content sync {Kind}/{Instance} ok: {Advisories} advisories, {Affects} affects, "
                + "{Patches} patches, {Edges} supersedence edges, {Overlays} overlays.",
                connector.Kind, instance, advisories, affects, patches, edges, overlays);

            return new SyncOutcome
            {
                Kind = connector.Kind,
                Instance = instance,
                Status = SyncOutcome.Ok,
                AdvisoriesUpserted = advisories,
                AffectsUpserted = affects,
                PatchesUpserted = patches,
                SupersedenceEdges = edges,
                OverlaysApplied = overlays,
                Cursor = batch.Cursor,
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Record the failure honestly and keep the OLD cursor (do not advance past unread data).
            // The message is a diagnostic; the feeds are public and unauthenticated, so it cannot
            // carry a credential, but we still never include a connection string here (NEVER #1).
            await store.UpdateSyncStatusAsync(
                conn, connector.Kind, instance, cursor, SyncOutcome.Failed, ex.Message, ct);

            logger.LogError(ex, "Content sync {Kind}/{Instance} failed.", connector.Kind, instance);

            return new SyncOutcome
            {
                Kind = connector.Kind,
                Instance = instance,
                Status = SyncOutcome.Failed,
                Cursor = cursor,
                Error = ex.Message,
            };
        }
    }
}
