using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Vault.Services;

/// <summary>
/// The ONLY shape in which a stored credential is described back to a caller: metadata only —
/// id, name, kind, scope, timestamps. It carries NO ciphertext, NO envelope, NO plaintext, and no
/// key material (CLAUDE.md NEVER #2). A contract test reflects over the vault's public surface and
/// fails if any returnable type ever grows a secret-bearing field.
/// </summary>
public sealed record CredentialSummary(
    Guid Id,
    string Name,
    CredentialKind Kind,
    string? TargetScope,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);
