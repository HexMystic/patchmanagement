using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Vault.Services;

/// <summary>
/// The write/admin side of the vault. Resolution (read side) is the frozen Phase 1
/// <see cref="ICredentialProvider"/>; this interface adds storing and metadata listing, which the
/// frozen contract intentionally does not cover. Every method is tenant-scoped via RLS and returns
/// metadata only — never secret material.
/// </summary>
public interface ICredentialVault
{
    /// <summary>
    /// Encrypt and store a credential for the current tenant, returning an opaque
    /// <see cref="CredentialRef"/>. The plaintext secret is used in memory only and never persisted
    /// outside its envelope. Audited (metadata only).
    /// </summary>
    Task<CredentialRef> StoreAsync(StoreCredentialRequest request, CancellationToken ct);

    /// <summary>List metadata for the current tenant's credentials. Never returns secret material.</summary>
    Task<IReadOnlyList<CredentialSummary>> ListAsync(CancellationToken ct);
}
