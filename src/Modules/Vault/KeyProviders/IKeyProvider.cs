namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The master-key custody abstraction (ADR 0002). The KEK — or, for a KMS, the ability to use it —
/// lives BEHIND this interface and never in the database. Implementations wrap/unwrap per-tenant
/// DEKs; only ciphertext and wrapped DEKs ever reach persistence.
///
/// Custody is pluggable and selected purely by config (<c>VAULT_KEY_PROVIDER</c>): the
/// <see cref="SoftwareKeyProvider"/> default works on-prem/air-gapped with zero external
/// dependency, while <c>AzureKeyVault</c>/<c>AwsKms</c>/<c>HashiCorpVault</c> keep the KEK inside
/// the customer's KMS/HSM.
///
/// The three verbs from phase-2.md (Wrap/Unwrap/Rotate) are the contract; <see cref="GetCurrentKeyIdAsync"/>
/// is added so a caller sealing a NEW DEK knows which live KEK version to wrap it with. A wrapped
/// DEK always records the <c>keyId</c> that sealed it, so unwrap selects the right KEK version and
/// rotation is zero-downtime.
/// </summary>
public interface IKeyProvider
{
    /// <summary>The identifier of the current (newest) KEK version — the one new DEKs are wrapped with.</summary>
    Task<string> GetCurrentKeyIdAsync(CancellationToken ct);

    /// <summary>
    /// Wrap (encrypt) a plaintext DEK under the KEK version <paramref name="keyId"/>, bound to
    /// <paramref name="binding"/> so the ciphertext cannot be moved to another row or tenant
    /// (ADR 0013).
    /// </summary>
    Task<byte[]> WrapAsync(byte[] dek, string keyId, KeyBinding binding, CancellationToken ct);

    /// <summary>
    /// Unwrap (decrypt) a wrapped DEK using the KEK version that sealed it. <paramref name="binding"/>
    /// must match the one used to wrap, or the unwrap fails authentication.
    /// </summary>
    Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, KeyBinding binding, CancellationToken ct);

    /// <summary>
    /// Create a new KEK version, make it current, and return its new <c>keyId</c>. The caller
    /// (the KEK-rotation service) then re-wraps every DEK under it. Old versions are retained so
    /// any not-yet-rewrapped DEK still unwraps — no credential is ever re-encrypted.
    /// </summary>
    Task<string> RotateMasterKeyAsync(CancellationToken ct);
}
