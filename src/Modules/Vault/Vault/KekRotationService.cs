using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Auditing;
using PatchManagement.Persistence;
using PatchManagement.Vault.KeyProviders;

namespace PatchManagement.Vault.Services;

/// <summary>
/// Implements zero-downtime KEK rotation. Steps:
/// <list type="number">
///   <item>Ask the <see cref="IKeyProvider"/> to create a new KEK version and make it current.</item>
///   <item>For every non-retired DEK across ALL tenants: unwrap it with the KEK version that sealed
///   it, re-wrap it under the new version, and update <c>wrapped_dek</c> + <c>key_id</c>.</item>
///   <item>Persist. No <c>credentials</c> row is read or written — the envelopes are untouched.</item>
/// </list>
/// Because old KEK versions are retained, a DEK not yet re-wrapped still unwraps, so the operation
/// is safe to retry and imposes no downtime.
///
/// M4 LIMITATION (flagged, not worked around): this is a SYSTEM-scope action spanning every tenant,
/// but the frozen <see cref="AuditEntry.TenantId"/> is non-nullable, so there is no way to write a
/// single tenant-agnostic "system rotated the KEK" record. We work within the contract by writing
/// ONE per-tenant audit entry for each tenant whose DEK moved — accurate and attributable — but a
/// true system-scope entry (and the operator who triggered it, independent of tenant) needs the
/// M4 change to make <c>AuditEntry.TenantId</c> nullable. See the report.
/// </summary>
public sealed class KekRotationService(
    AppDbContext db,
    IKeyProvider keyProvider,
    IAuditLog audit,
    IVaultActor actor,
    ILogger<KekRotationService> logger) : IKekRotationService
{
    public async Task<KekRotationResult> RotateAsync(CancellationToken ct)
    {
        var newKeyId = await keyProvider.RotateMasterKeyAsync(ct);

        var deks = await db.DataKeys.Where(k => k.RetiredAt == null).ToListAsync(ct);
        var tenants = new HashSet<Guid>();

        foreach (var dek in deks)
        {
            if (dek.WrappedDek is null || dek.KeyId is null)
                continue; // never sealed — nothing to re-wrap

            // Built per row: this loop crosses tenants on an owner context, so the binding must not
            // be hoisted. Identical for unwrap and re-wrap because key_id is deliberately excluded
            // from the binding — only the KEK version changes here, not the row's identity (ADR 0013).
            var binding = new KeyBinding(dek.TenantId, dek.Id);

            var plaintext = await keyProvider.UnwrapAsync(dek.WrappedDek, dek.KeyId, binding, ct);
            try
            {
                dek.WrappedDek = await keyProvider.WrapAsync(plaintext, newKeyId, binding, ct);
                dek.KeyId = newKeyId;
                tenants.Add(dek.TenantId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        await db.SaveChangesAsync(ct);

        // Per-tenant audit (M4 limitation above). Metadata only — never key material.
        foreach (var tenantId in tenants)
        {
            var detail = JsonSerializer.Serialize(new
            {
                newKeyId,
                deksRewrapped = deks.Count(d => d.TenantId == tenantId),
                credentialsReencrypted = 0,
            });
            await audit.AppendAsync(
                new AuditEntry(tenantId, actor.Name, "kek.rotate", $"kek:{newKeyId}", DateTimeOffset.UtcNow, detail),
                ct);
        }

        logger.LogInformation(
            "Rotated KEK to {NewKeyId}: re-wrapped {DekCount} DEK(s) across {TenantCount} tenant(s); 0 credentials re-encrypted",
            newKeyId, deks.Count, tenants.Count);

        return new KekRotationResult(newKeyId, deks.Count, tenants.Count);
    }
}
