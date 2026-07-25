using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Vault.Services;

/// <summary>
/// Input to <see cref="ICredentialVault.StoreAsync"/>. The <see cref="Secret"/> is the ONLY secret
/// field and exists in memory only for the duration of the store; the vault copies it into a pinned
/// buffer, encrypts, and the caller is expected to clear its own copy. This type is an INPUT DTO —
/// it is never serialized to a response, and the never-return contract test excludes inputs by
/// asserting on the vault's OUTPUT surface.
///
/// <para><b><see cref="Secret"/> must stay <c>byte[]</c>.</b> This is a record, so its
/// compiler-generated <c>ToString()</c> prints every property — today <c>byte[]</c> renders as
/// "System.Byte[]", but as a <c>string</c> the secret would be printed verbatim by any
/// <c>LogInformation("{Request}", request)</c>. Pinned by <c>VaultLoggingConventionTests</c>;
/// see ADR 0012 (docs/adr/0012-log-redaction-scope.md).</para>
/// </summary>
public sealed record StoreCredentialRequest(
    string Name,
    CredentialKind Kind,
    byte[] Secret,
    string? Username = null,
    string? TargetScope = null);
