namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// Identifies the row a wrapped DEK belongs to, so a provider can bind the ciphertext to it and a
/// relocated <c>data_keys</c> row fails to unwrap. See ADR 0013.
///
/// <para>Typed rather than raw associated-data bytes because the backends express this differently:
/// the software provider canonicalises it to AES-GCM associated data, AWS KMS would map it to an
/// <c>EncryptionContext</c> dictionary, and HashiCorp Transit to its <c>context</c> field. Raw bytes
/// would fit only the first. Azure Key Vault's <c>wrapKey</c> has no binding parameter at all, which
/// is recorded as a limitation on that provider rather than papered over here.</para>
/// </summary>
/// <param name="TenantId">Owning tenant of the <c>data_keys</c> row.</param>
/// <param name="DataKeyId">Primary key of the <c>data_keys</c> row.</param>
public readonly record struct KeyBinding(Guid TenantId, Guid DataKeyId);
