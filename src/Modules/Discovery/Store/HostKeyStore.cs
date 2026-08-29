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
    public async Task<PinnedHostKey?> FindTrustedAsync(
        Guid tenantId, string host, int port, CancellationToken ct)
    {
        // A partial unique index admits at most one trusted key per endpoint, so "which key do we
        // trust" has exactly one answer and SingleOrDefault is the honest query — a FirstOrDefault
        // here would quietly pick one of two if that invariant ever broke.
        var pinned = await db.HostKeys
            .AsNoTracking()
            .Where(k => k.TenantId == tenantId
                        && k.Host == host
                        && k.Port == port
                        && k.Status == HostKeyStatuses.Trusted)
            .Select(k => new PinnedHostKey(k.KeyAlgorithm, k.FingerprintSha256))
            .SingleOrDefaultAsync(ct)
            .ConfigureAwait(false);

        return pinned;
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
