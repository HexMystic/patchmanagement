namespace PatchManagement.Contracts.Credentials;

/// <summary>
/// Resolves a <see cref="CredentialRef"/> to an in-memory-only <see cref="ResolvedCredential"/>.
///
/// Defined in Phase 1 contracts so the Phase 3 connector can be built and tested (with a
/// <c>FakeCredentialProvider</c> test double) IN PARALLEL with the Phase 2 vault, which
/// provides the production implementation. Consumers depend on this interface only — never
/// on the vault implementation, envelope encryption, or key providers.
/// </summary>
public interface ICredentialProvider
{
    /// <summary>
    /// Resolve <paramref name="reference"/> to its secret material. The returned credential
    /// is memory-only and should be disposed after use. Never logs or returns the secret.
    /// </summary>
    Task<ResolvedCredential> ResolveAsync(CredentialRef reference, CancellationToken ct);
}
