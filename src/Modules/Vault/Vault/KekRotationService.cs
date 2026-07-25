using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Auditing;
using PatchManagement.Contracts.Tenancy;
using PatchManagement.Persistence;
using PatchManagement.Vault.KeyProviders;

namespace PatchManagement.Vault.Services;

/// <summary>
/// Implements zero-downtime KEK rotation as a per-tenant sweep.
/// <list type="number">
///   <item>Ask the <see cref="IKeyProvider"/> for the KEK version to converge onto — a freshly minted
///   one for <see cref="RotateAsync"/>, the existing current one for
///   <see cref="CompleteRotationAsync"/>.</item>
///   <item>For each tenant, in its own scope: re-wrap that tenant's DEKs onto the target version,
///   save, and audit.</item>
///   <item>No <c>credentials</c> row is read or written — the envelopes are untouched.</item>
/// </list>
///
/// <para><b>Tenancy (review C1).</b> This does not use — and does not need — an RLS-exempt context.
/// It sweeps tenants via <see cref="ITenantScopeFactory"/>, each scope running as the ordinary
/// restricted role with the tenant policy enforced. Previously it was registered against the
/// request-path context, so off the HTTP path it saw zero rows and reported success. See ADR 0014.</para>
///
/// <para><b>Isolation and resumability.</b> Every DEK is re-wrapped inside its own try/catch, so a
/// corrupt or relocated row fails alone: its tenant's other DEKs still converge, other tenants are
/// untouched, and the failure is reported rather than thrown. Because old KEK versions are retained,
/// a DEK not yet re-wrapped still unwraps — so a partial run is finished by calling
/// <see cref="CompleteRotationAsync"/>, which converges the stragglers WITHOUT minting another key.
/// Retrying <see cref="RotateAsync"/> would mint one per attempt.</para>
///
/// <para><b>Batching.</b> The per-tenant scope is the batch and the commit boundary: each tenant
/// saves and audits on its own, so no single transaction spans the estate. The working set is
/// O(tenants) — roughly one active DEK each — not O(endpoints).</para>
///
/// <para>M4 LIMITATION (flagged, not worked around): this is a SYSTEM-scope action spanning every
/// tenant, but the frozen <see cref="AuditEntry.TenantId"/> is non-nullable, so there is no way to
/// write a single tenant-agnostic "system rotated the KEK" record. Writing one entry per tenant
/// inside that tenant's own scope is accurate and attributable, and satisfies the audit policy's
/// WITH CHECK naturally. See docs/reviews/phase-1-review.md (M4).</para>
/// </summary>
public sealed class KekRotationService(
    ITenantScopeFactory tenantScopes,
    IKeyProvider keyProvider,
    IVaultActor actor,
    ILogger<KekRotationService> logger) : IKekRotationService
{
    /// <summary>
    /// Serialises whole rotations within this process. This service is a singleton, so two callers
    /// share one instance — and without this they interleave destructively: A mints k1, B mints k2,
    /// and A's still-running sweep converges the estate onto k1, by then superseded. After a breach
    /// that silently restores the compromised key, and both callers are told it worked. It also
    /// protects <see cref="ConvergeAsync"/>'s captured counters, which are only safe because one
    /// sweep runs at a time (cold review H2).
    ///
    /// <para>The gate must span the MINT as well as the sweep. Guarding only the sweep still allows
    /// both mints to land first, which is the same defect with extra steps.</para>
    ///
    /// <para>In-process only, and that limit is real: a second process rotating concurrently is not
    /// excluded by this and remains open (ADR 0016, Phase 15). What IS excluded here is the case
    /// ADR 0016 originally — and wrongly — filed as multi-process-only.</para>
    /// </summary>
    private readonly SemaphoreSlim _rotationGate = new(1, 1);

    public Task<KekRotationResult> RotateAsync(CancellationToken ct) =>
        ExclusivelyAsync(async token =>
        {
            var newKeyId = await keyProvider.RotateMasterKeyAsync(token);
            return await ConvergeAsync(newKeyId, token);
        }, ct);

    public Task<KekRotationResult> CompleteRotationAsync(CancellationToken ct) =>
        ExclusivelyAsync(async token =>
        {
            // Authoritative, not cached. Targeting a remembered-but-superseded version would select
            // every DEK another process already moved forward and re-wrap the estate BACKWARDS onto
            // it — after a breach, silently restoring the compromised key (re-review C-A).
            var currentKeyId = await keyProvider.RefreshCurrentKeyIdAsync(token);
            return await ConvergeAsync(currentKeyId, token);
        }, ct);

    /// <summary>
    /// Runs one rotation at a time. Callers queue rather than being refused: a
    /// <see cref="CompleteRotationAsync"/> waiting behind a <see cref="RotateAsync"/> is exactly the
    /// "finish the partial run" case, and two serialised <see cref="RotateAsync"/> calls each mint
    /// and converge truthfully — the second simply supersedes the first. Waiting honours the
    /// caller's token, so this cannot become an unbounded block.
    /// </summary>
    private async Task<KekRotationResult> ExclusivelyAsync(
        Func<CancellationToken, Task<KekRotationResult>> rotation, CancellationToken ct)
    {
        if (!await _rotationGate.WaitAsync(0, ct))
        {
            logger.LogInformation(
                "A KEK rotation is already in progress in this process; queuing behind it");
            await _rotationGate.WaitAsync(ct);
        }

        try
        {
            return await rotation(ct);
        }
        finally
        {
            _rotationGate.Release();
        }
    }

    /// <summary>Re-wrap every DEK not already on <paramref name="targetKeyId"/>, tenant by tenant.</summary>
    private async Task<KekRotationResult> ConvergeAsync(string targetKeyId, CancellationToken ct)
    {
        // Mutated only from the sweep body, which runs tenants sequentially, and only one sweep runs
        // at a time (_rotationGate).
        //
        // WARNING FOR THE 10,000-ENDPOINT WORK: parallelising SweepAsync silently corrupts these.
        // They are plain captured locals with no interlocking, and `failures` is a bare List<T>.
        // Anyone adding concurrency to the sweep must convert this accounting first — a rotation
        // that miscounts is a rotation that misreports, and this subsystem has already produced that
        // defect four times (cold review M5; see KekRotationResult.Complete).
        var rewrapped = 0;
        var skipped = 0;
        var failures = new List<KekRotationFailure>();

        var sweep = await tenantScopes.SweepAsync("kek.rotate", async (scope, token) =>
        {
            var db = scope.Services.GetRequiredService<AppDbContext>();
            var audit = scope.Services.GetRequiredService<IAuditLog>();

            // Only what still needs moving — this is what makes a retry converge rather than redo.
            var deks = await db.DataKeys
                .Where(k => k.RetiredAt == null && k.KeyId != targetKeyId)
                .ToListAsync(token);

            var moved = 0;
            foreach (var dek in deks)
            {
                // A tenant with many DEKs was otherwise interruptible only through whatever I/O
                // happened to be awaited next (CLAUDE.md NEVER #5 — time-bounded). Throwing here
                // abandons the change tracker before any save, so nothing partial can commit.
                token.ThrowIfCancellationRequested();

                if (dek.WrappedDek is null || dek.KeyId is null)
                {
                    // NOT benign, and not silent. Every DEK DataKeyService creates is sealed, so a
                    // LIVE row with no material is corrupt or tampered — and it stays on its old KEK
                    // version. Counting it and moving on let a DB-write adversary NULL chosen rows,
                    // collect a Complete=true rotation, then restore the original pair: those
                    // credentials survive a post-breach rotation, of the attacker's choosing, and the
                    // operator has been told there is nothing to re-run (cold review H1).
                    skipped++;
                    failures.Add(new KekRotationFailure(
                        dek.TenantId, dek.Id, "Unconvergeable: the row has no wrapped material or no key id."));
                    logger.LogWarning(
                        "DEK {DataKeyId} (tenant {TenantId}) has no wrapped material and cannot be "
                        + "converged; it remains on its previous KEK version",
                        dek.Id, dek.TenantId);
                    continue;
                }

                try
                {
                    // key_id is excluded from the binding, so it is identical either side of the
                    // re-wrap — only the KEK version changes, not the row's identity (ADR 0013).
                    var binding = new KeyBinding(dek.TenantId, dek.Id);
                    var plaintext = await keyProvider.UnwrapAsync(dek.WrappedDek, dek.KeyId, binding, token);
                    try
                    {
                        dek.WrappedDek = await keyProvider.WrapAsync(plaintext, targetKeyId, binding, token);
                        dek.KeyId = targetKeyId;
                        moved++;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // One poisoned row must not cost the estate. Nothing was mutated on this entity —
                    // the assignment only happens after a successful wrap — so the save below is clean.
                    failures.Add(new KekRotationFailure(dek.TenantId, dek.Id, $"{ex.GetType().Name}: {ex.Message}"));
                    logger.LogWarning(
                        "DEK {DataKeyId} (tenant {TenantId}) could not be re-wrapped ({ExceptionType}); continuing",
                        dek.Id, dek.TenantId, ex.GetType().Name);
                }
            }

            if (moved == 0) return;

            // Last point at which cancelling is free. Past the save, the key change is durable and
            // abandoning the audit would leave it unrecorded (re-review H-B).
            token.ThrowIfCancellationRequested();

            // Save first, then audit: EfAuditLog saves the shared context, so auditing mid-loop would
            // flush half-converged state (review M4, second half).
            await db.SaveChangesAsync(token);
            rewrapped += moved;

            var detail = JsonSerializer.Serialize(new
            {
                keyId = targetKeyId,
                deksRewrapped = moved,
                credentialsReencrypted = 0,
            });

            // CancellationToken.None, deliberately, and the one place in this module that departs
            // from "a token on every I/O". The re-wrap above is ALREADY COMMITTED; this append is
            // its only record. Honouring a cancel here would silently trade a key change for no
            // audit trail — and a KEK rotation nobody can prove happened is the failure mode this
            // service exists to avoid. The append is a bounded single-row insert.
            //
            // Residual, not closed here: a crash (rather than a cancel) between the two writes still
            // loses the row. The real fix is one transaction, which needs EfAuditLog to stop saving
            // the caller's context — Phase-1 review M4, owned by Phase 13.
            await audit.AppendAsync(
                new AuditEntry(scope.TenantId, actor.Name, "kek.rotate", $"kek:{targetKeyId}",
                    DateTimeOffset.UtcNow, detail),
                CancellationToken.None);
        }, ct);

        // sweep.Failures carries tenants whose scope threw OUTSIDE the per-DEK try — a dropped
        // connection on the query, a failed save, a failed audit append. Dropping them would report
        // Complete for a rotation that never touched those tenants (re-review H-A).
        var result = new KekRotationResult(
            targetKeyId, sweep.TenantsTotal, sweep.TenantsAttempted, rewrapped, skipped,
            failures, sweep.Failures);

        logger.LogInformation(
            "Converged on KEK {KeyId}: re-wrapped {DekCount} DEK(s) across {Attempted}/{Total} tenant(s); "
            + "{Skipped} skipped, {DekFailed} DEK failure(s), {TenantFailed} tenant failure(s); "
            + "0 credentials re-encrypted",
            targetKeyId, rewrapped, sweep.TenantsAttempted, sweep.TenantsTotal, skipped,
            failures.Count, sweep.Failures.Count);

        return result;
    }
}
