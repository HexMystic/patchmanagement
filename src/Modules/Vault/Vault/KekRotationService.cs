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
    public async Task<KekRotationResult> RotateAsync(CancellationToken ct)
    {
        var newKeyId = await keyProvider.RotateMasterKeyAsync(ct);
        return await ConvergeAsync(newKeyId, ct);
    }

    public async Task<KekRotationResult> CompleteRotationAsync(CancellationToken ct)
    {
        var currentKeyId = await keyProvider.GetCurrentKeyIdAsync(ct);
        return await ConvergeAsync(currentKeyId, ct);
    }

    /// <summary>Re-wrap every DEK not already on <paramref name="targetKeyId"/>, tenant by tenant.</summary>
    private async Task<KekRotationResult> ConvergeAsync(string targetKeyId, CancellationToken ct)
    {
        // Mutated only from the sweep body, which runs tenants sequentially.
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
                if (dek.WrappedDek is null || dek.KeyId is null)
                {
                    skipped++; // never sealed — nothing to re-wrap
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
            await audit.AppendAsync(
                new AuditEntry(scope.TenantId, actor.Name, "kek.rotate", $"kek:{targetKeyId}",
                    DateTimeOffset.UtcNow, detail),
                token);
        }, ct);

        var result = new KekRotationResult(
            targetKeyId, sweep.TenantsTotal, sweep.TenantsAttempted, rewrapped, skipped, failures);

        logger.LogInformation(
            "Converged on KEK {KeyId}: re-wrapped {DekCount} DEK(s) across {Attempted}/{Total} tenant(s); "
            + "{Skipped} skipped, {Failed} failed; 0 credentials re-encrypted",
            targetKeyId, rewrapped, sweep.TenantsAttempted, sweep.TenantsTotal, skipped, failures.Count);

        return result;
    }
}
