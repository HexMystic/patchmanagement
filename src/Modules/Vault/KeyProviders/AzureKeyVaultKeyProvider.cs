namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// Opt-in KMS custody: the KEK lives in Azure Key Vault and never on the app host; wrap/unwrap
/// happen inside the vault (ADR 0002, THREAT-MODEL). STUB — the interface is frozen here so callers
/// and DI selection are wired, but the wrap/unwrap calls to Key Vault are a later increment. It is
/// deliberately loud rather than silently returning fake ciphertext.
/// </summary>
public sealed class AzureKeyVaultKeyProvider : IKeyProvider
{
    private const string NotImplemented =
        "AzureKeyVaultKeyProvider is a Phase 2 stub. Set VAULT_KEY_PROVIDER=software to use the " +
        "on-prem software provider, or implement the Key Vault wrap/unwrap calls.";

    public Task<string> GetCurrentKeyIdAsync(CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<byte[]> WrapAsync(byte[] dek, string keyId, CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<string> RotateMasterKeyAsync(CancellationToken ct) => throw new NotImplementedException(NotImplemented);
}
