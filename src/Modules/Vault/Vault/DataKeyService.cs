using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using PatchManagement.Vault.Crypto;
using PatchManagement.Vault.KeyProviders;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Entities;
using PatchManagement.Persistence.Rls;

namespace PatchManagement.Vault.Services;

/// <summary>
/// Manages per-tenant data keys (DEKs): the middle layer of the envelope. A DEK is a 256-bit key
/// generated per tenant, stored ONLY as ciphertext (KEK-wrapped) in <c>data_keys</c>, and used to
/// seal that tenant's credential envelopes.
///
/// Reads/writes go through the RLS-scoped <see cref="AppDbContext"/>, so a DEK is only ever visible
/// to its own tenant (per-tenant blast-radius containment, THREAT-MODEL). Plaintext DEK material
/// only ever exists inside a <see cref="PinnedBuffer"/> that the caller zeroes immediately after use.
/// </summary>
public sealed class DataKeyService(AppDbContext db, IKeyProvider keyProvider, ITenantContext tenant)
{
    /// <summary>
    /// The tenant's current (non-retired) DEK, creating one on first use. The returned entity holds
    /// only the WRAPPED key; call <see cref="UnwrapAsync"/> to get plaintext into a pinned buffer.
    /// </summary>
    public async Task<DataKey> GetOrCreateActiveAsync(CancellationToken ct)
    {
        var tenantId = RequireTenant();

        var existing = await db.DataKeys
            .Where(k => k.RetiredAt == null)
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefaultAsync(ct);
        if (existing is not null) return existing;

        var keyId = await keyProvider.GetCurrentKeyIdAsync(ct);

        // Generate the DEK straight into a pinned buffer, wrap it, and never keep the plaintext.
        using var dek = new PinnedBuffer(AesGcmEnvelope.KeySizeBytes);
        RandomNumberGenerator.Fill(dek.Span);
        var wrapped = await keyProvider.WrapAsync(dek.Bytes, keyId, ct);

        var now = DateTimeOffset.UtcNow;
        var entity = new DataKey
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            WrappedDek = wrapped,
            KeyId = keyId,
            CreatedAt = now,
        };
        db.DataKeys.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    /// <summary>
    /// Unwrap a DEK into a pinned buffer using the KEK version recorded on the row. The caller owns
    /// the buffer and MUST dispose it (which zeroes it). Never logs the plaintext.
    /// </summary>
    internal async Task<PinnedBuffer> UnwrapAsync(DataKey dek, CancellationToken ct)
    {
        if (dek.WrappedDek is null || dek.KeyId is null)
            throw new InvalidOperationException($"DataKey {dek.Id} has no wrapped material — cannot unwrap.");

        var plaintext = await keyProvider.UnwrapAsync(dek.WrappedDek, dek.KeyId, ct);
        try
        {
            var buffer = new PinnedBuffer(plaintext.Length);
            plaintext.CopyTo(buffer.Bytes, 0);
            return buffer;
        }
        finally
        {
            // The intermediate managed array handed back by the provider must not linger.
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private Guid RequireTenant() =>
        tenant.TenantId ?? throw new InvalidOperationException(
            "No tenant context is set. Credential operations are tenant-scoped and fail closed.");
}
