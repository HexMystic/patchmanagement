using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Persistence.Entities;

/// <summary>
/// A stored endpoint credential. Phase 1 defines the shape only; the Phase 2 vault fills
/// <see cref="Envelope"/> (ciphertext) and <see cref="DataKeyId"/>. No plaintext ever lives here.
/// </summary>
public sealed class Credential
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Name { get; set; } = string.Empty;
    public CredentialKind Kind { get; set; }

    /// <summary>Envelope-encrypted secret (AES-GCM under a per-tenant DEK). Set by Phase 2.</summary>
    public byte[]? Envelope { get; set; }

    /// <summary>The data key this credential's envelope was sealed with. Set by Phase 2.</summary>
    public Guid? DataKeyId { get; set; }

    /// <summary>Optional scope narrowing where this credential may be used.</summary>
    public string? TargetScope { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
