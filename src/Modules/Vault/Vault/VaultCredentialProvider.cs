using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Auditing;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Entities;
using PatchManagement.Persistence.Rls;
using PatchManagement.Vault.Crypto;

namespace PatchManagement.Vault.Services;

/// <summary>
/// The production vault: implements the frozen read side (<see cref="ICredentialProvider"/>) and
/// the write side (<see cref="ICredentialVault"/>). Credentials are sealed with a per-tenant DEK
/// (AES-256-GCM) and stored as an opaque envelope; decryption is in-memory only, into pinned
/// buffers zeroed immediately after use (THREAT-MODEL).
///
/// INVARIANTS enforced here:
/// <list type="bullet">
///   <item><b>Never returned</b> (NEVER #2): the only outputs are <see cref="CredentialRef"/>,
///   <see cref="CredentialSummary"/> and the memory-only <see cref="ResolvedCredential"/>. No
///   ciphertext or plaintext is ever placed on a returnable DTO.</item>
///   <item><b>Never logged</b> (NEVER #1): every log statement here carries metadata only — id,
///   kind, outcome. Secret material is never passed to the logger, and the logger scope carries no
///   secret. Proven by a log-scanning test.</item>
///   <item><b>Every access audited</b>: resolve and store both append an <see cref="AuditEntry"/>
///   (metadata only) via the Phase 1 <see cref="IAuditLog"/>.</item>
/// </list>
/// </summary>
public sealed class VaultCredentialProvider(
    AppDbContext db,
    DataKeyService dataKeys,
    IAuditLog audit,
    IVaultActor actor,
    ITenantContext tenant,
    ILogger<VaultCredentialProvider> logger) : ICredentialProvider, ICredentialVault
{
    public async Task<CredentialRef> StoreAsync(StoreCredentialRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Secret);
        var tenantId = RequireTenant();

        var dek = await dataKeys.GetOrCreateActiveAsync(ct);
        using var dekPlain = await dataKeys.UnwrapAsync(dek, ct);

        // Assemble the payload (username + secret) in a pinned buffer, seal it, then let the buffer
        // zero itself. The only persisted form is the authenticated ciphertext.
        var payloadSize = CredentialPayload.Size(request.Username, request.Secret.Length);
        byte[] envelope;
        using (var payload = new PinnedBuffer(payloadSize))
        {
            var written = CredentialPayload.Write(payload.Span, request.Username, request.Secret);
            envelope = AesGcmEnvelope.Seal(dekPlain.Span, payload.Span[..written]);
        }

        var now = DateTimeOffset.UtcNow;
        var entity = new Credential
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            Name = request.Name,
            Kind = request.Kind,
            Envelope = envelope,
            DataKeyId = dek.Id,
            TargetScope = request.TargetScope,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.Credentials.Add(entity);
        await db.SaveChangesAsync(ct);

        logger.LogInformation(
            "Stored credential {CredentialId} (kind {Kind}) for tenant {TenantId}",
            entity.Id, entity.Kind, tenantId);
        await AuditAsync(tenantId, "credential.store", entity.Id, entity.Kind, "stored", ct);

        return new CredentialRef(entity.Id, entity.TargetScope);
    }

    public async Task<ResolvedCredential> ResolveAsync(CredentialRef reference, CancellationToken ct)
    {
        var tenantId = RequireTenant();

        var credential = await db.Credentials.FirstOrDefaultAsync(c => c.Id == reference.Id, ct);
        if (credential is null || credential.Envelope is null || credential.DataKeyId is null)
        {
            logger.LogWarning("Credential {CredentialId} not found or not sealed for tenant {TenantId}",
                reference.Id, tenantId);
            await AuditAsync(tenantId, "credential.resolve", reference.Id, kind: null, "not-found", ct);
            throw new KeyNotFoundException($"Credential {reference.Id} was not found for this tenant.");
        }

        var dek = await db.DataKeys.FirstOrDefaultAsync(k => k.Id == credential.DataKeyId, ct)
            ?? throw new InvalidOperationException(
                $"Credential {credential.Id} references missing data key {credential.DataKeyId}.");

        using var dekPlain = await dataKeys.UnwrapAsync(dek, ct);

        // Decrypt into a pinned buffer, copy the secret into the frozen ResolvedCredential's array,
        // then let the pinned plaintext zero itself. The unpinned final copy is the documented M7
        // limitation of the frozen contract.
        var plaintextLength = AesGcmEnvelope.PlaintextLength(credential.Envelope);
        using var plaintext = new PinnedBuffer(plaintextLength);
        var written = AesGcmEnvelope.Open(dekPlain.Span, credential.Envelope, plaintext.Span);
        var secret = CredentialPayload.Read(plaintext.Span[..written], out var username);
        var secretCopy = secret.ToArray();

        logger.LogInformation(
            "Resolved credential {CredentialId} (kind {Kind}) for tenant {TenantId}",
            credential.Id, credential.Kind, tenantId);
        await AuditAsync(tenantId, "credential.resolve", credential.Id, credential.Kind, "resolved", ct);

        return new ResolvedCredential(credential.Kind, secretCopy, username);
    }

    public async Task<IReadOnlyList<CredentialSummary>> ListAsync(CancellationToken ct)
    {
        RequireTenant();
        return await db.Credentials
            .OrderBy(c => c.Name)
            .Select(c => new CredentialSummary(c.Id, c.Name, c.Kind, c.TargetScope, c.CreatedAt, c.UpdatedAt))
            .ToListAsync(ct);
    }

    private async Task AuditAsync(
        Guid tenantId, string action, Guid credentialId, CredentialKind? kind, string outcome, CancellationToken ct)
    {
        // Metadata only — never the secret. Detail is jsonb, so it must be valid JSON.
        var detail = JsonSerializer.Serialize(new
        {
            credentialId,
            kind = kind?.ToString(),
            outcome,
        });
        await audit.AppendAsync(
            new AuditEntry(tenantId, actor.Name, action, $"cred:{credentialId}", DateTimeOffset.UtcNow, detail),
            ct);
    }

    private Guid RequireTenant() =>
        tenant.TenantId ?? throw new InvalidOperationException(
            "No tenant context is set. Credential operations are tenant-scoped and fail closed.");
}
