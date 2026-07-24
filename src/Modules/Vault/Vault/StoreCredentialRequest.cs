using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Vault.Services;

/// <summary>
/// Input to <see cref="ICredentialVault.StoreAsync"/>. The <see cref="Secret"/> is the ONLY secret
/// field and exists in memory only for the duration of the store; the vault copies it into a pinned
/// buffer, encrypts, and the caller is expected to clear its own copy. This type is an INPUT DTO —
/// it is never serialized to a response, and the never-return contract test excludes inputs by
/// asserting on the vault's OUTPUT surface.
/// </summary>
public sealed record StoreCredentialRequest(
    string Name,
    CredentialKind Kind,
    byte[] Secret,
    string? Username = null,
    string? TargetScope = null);
