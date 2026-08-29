using Microsoft.EntityFrameworkCore;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Entities;

namespace PatchManagement.Discovery.Store;

/// <summary>
/// The <see cref="IHostKeyStore"/> over <see cref="AppDbContext"/> — D-301's store, living with
/// asset persistence because a fingerprint is another observed fact about an endpoint
/// (HARD-PROBLEMS #11). Every read and write goes through the RLS-intercepted context, so tenant
/// isolation is the database's guarantee rather than this class remembering to filter.
///
/// <para><b>Nothing here is secret.</b> A host key is public material, so it is stored verbatim
/// alongside its fingerprint; NEVER #1/#2 are not engaged.</para>
/// </summary>
internal sealed class HostKeyStore(AppDbContext db, TimeProvider time) : IHostKeyStore
{
    public async Task<EndpointHostKeys> FindAsync(
        Guid tenantId, string host, int port, CancellationToken ct)
    {
        // One read for the whole endpoint. Fetching only the pin would make a revoked key on an
        // otherwise-unpinned endpoint indistinguishable from a first sighting, which is precisely how
        // a withdrawn key came to be accepted on every connection.
        var rows = await db.HostKeys
            .AsNoTracking()
            .Where(k => k.TenantId == tenantId && k.Host == host && k.Port == port)
            .Select(k => new { k.Status, k.KeyAlgorithm, k.FingerprintSha256 })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        // A partial unique index admits at most one trusted key per endpoint, so "which key do we
        // trust" has exactly one answer and Single is the honest query — First would quietly pick
        // one of two if that invariant ever broke.
        var trusted = rows.SingleOrDefault(r => r.Status == HostKeyStatuses.Trusted);

        var closed = rows
            .Where(r => HostKeyStatuses.Closed.Contains(r.Status))
            .Select(r => r.FingerprintSha256)
            .ToArray();

        return new EndpointHostKeys(
            trusted is null ? null : new PinnedHostKey(trusted.KeyAlgorithm, trusted.FingerprintSha256),
            closed);
    }

    public async Task RecordAsync(HostKeyObservation observation, CancellationToken ct)
    {
        var now = time.GetUtcNow();

        // Keyed on the FINGERPRINT, not the endpoint: an endpoint legitimately accumulates rows over
        // its life (a pinned key, then the replacement awaiting review). Re-seeing a key already on
        // file advances when it was last seen rather than adding a duplicate — otherwise every
        // refused reconnect would append another pending row until the table was mostly noise.
        var existing = await db.HostKeys
            .SingleOrDefaultAsync(
                k => k.TenantId == observation.TenantId
                     && k.Host == observation.Host
                     && k.Port == observation.Port
                     && k.FingerprintSha256 == observation.FingerprintSha256,
                ct)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            existing.LastVerifiedAt = now;

            // Promote rather than duplicate. A key refused under a strict policy is already on file
            // as pending; when the deployment opts into first-sight pinning, THIS row must become the
            // pin. Leaving it pending would accept the key on every connection while the endpoint
            // stayed permanently unverified — working, and unpinned.
            //
            // Only ever from pending: a closed row cannot reach here, because a closed fingerprint
            // judges Withdrawn and never PinnedOnFirstSight.
            if (observation.Verdict is HostKeyVerdict.PinnedOnFirstSight
                && existing.Status == HostKeyStatuses.Pending)
            {
                existing.Status = HostKeyStatuses.Trusted;
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return;
        }

        db.HostKeys.Add(new HostKey
        {
            Id = Guid.NewGuid(),
            TenantId = observation.TenantId,
            Host = observation.Host,
            Port = observation.Port,
            KeyAlgorithm = observation.KeyAlgorithm,
            FingerprintSha256 = observation.FingerprintSha256,
            PublicKey = observation.PublicKey,

            // Only a first sighting under a pinning policy becomes the pin. Everything else is
            // recorded as PENDING — seen, not accepted — which is what makes a refusal auditable
            // instead of merely fatal.
            Status = observation.Verdict is HostKeyVerdict.PinnedOnFirstSight
                ? HostKeyStatuses.Trusted
                : HostKeyStatuses.Pending,

            FirstSeenAt = now,
            LastVerifiedAt = now,
            CreatedAt = now,
        });

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }
}
