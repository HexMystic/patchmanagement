namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// Opt-in KMS custody: the KEK lives in HashiCorp Vault's transit engine and never on the app host
/// (ADR 0002, THREAT-MODEL). STUB — see <see cref="AzureKeyVaultKeyProvider"/> for the rationale.
///
/// <para>Binding (ADR 0013): a <see cref="KeyBinding"/> maps onto the transit engine's
/// <c>context</c> parameter (derived keys), which must then be supplied identically on decrypt —
/// the same row-binding guarantee as the software provider's associated data.</para>
/// </summary>
public sealed class HashiCorpVaultKeyProvider : IKeyProvider
{
    private const string NotImplemented =
        "HashiCorpVaultKeyProvider is a Phase 2 stub. Set VAULT_KEY_PROVIDER=software to use the " +
        "on-prem software provider, or implement the transit-engine wrap/unwrap calls.";

    public Task<string> GetCurrentKeyIdAsync(CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<string> RefreshCurrentKeyIdAsync(CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<byte[]> WrapAsync(byte[] dek, string keyId, KeyBinding binding, CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, KeyBinding binding, CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<string> RotateMasterKeyAsync(CancellationToken ct) => throw new NotImplementedException(NotImplemented);
}
