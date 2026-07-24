namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// Opt-in KMS custody: the KEK lives in AWS KMS and never on the app host; wrap/unwrap happen via
/// KMS (ADR 0002, THREAT-MODEL). STUB — see <see cref="AzureKeyVaultKeyProvider"/> for the rationale.
/// </summary>
public sealed class AwsKmsKeyProvider : IKeyProvider
{
    private const string NotImplemented =
        "AwsKmsKeyProvider is a Phase 2 stub. Set VAULT_KEY_PROVIDER=software to use the on-prem " +
        "software provider, or implement the KMS Encrypt/Decrypt calls.";

    public Task<string> GetCurrentKeyIdAsync(CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<byte[]> WrapAsync(byte[] dek, string keyId, CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, CancellationToken ct) => throw new NotImplementedException(NotImplemented);
    public Task<string> RotateMasterKeyAsync(CancellationToken ct) => throw new NotImplementedException(NotImplemented);
}
