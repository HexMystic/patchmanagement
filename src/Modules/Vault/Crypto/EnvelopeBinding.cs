using System.Text;

namespace PatchManagement.Vault.Crypto;

/// <summary>
/// Builds the AES-GCM associated data that binds a ciphertext to the ROW it is stored in.
///
/// <para>Without this, an envelope is a free-floating blob: it decrypts under any row that points at
/// the key that sealed it. An adversary with database write access — a named adversary in
/// THREAT-MODEL — could copy a wrapped DEK and a sealed envelope into another tenant's rows, satisfy
/// RLS and the composite foreign key, and have the application itself decrypt one tenant's
/// credential for another. Associated data makes that relocation fail authentication.</para>
///
/// <para>The binding is a canonical UTF-8 string rather than packed bytes so it is auditable and
/// endian-independent (<c>Guid:N</c> has one representation everywhere). The leading domain label
/// separates the two envelope layers, so a credential binding can never collide with a data-key
/// binding, and <c>v2</c> ties the binding to the envelope format version — a downgrade cannot be
/// forged. See ADR 0013.</para>
/// </summary>
internal static class EnvelopeBinding
{
    /// <summary>Domain label for a credential payload sealed under a DEK.</summary>
    public const string CredentialDomain = "patchmgmt:v2:credential";

    /// <summary>Domain label for a DEK wrapped under a KEK.</summary>
    public const string DataKeyDomain = "patchmgmt:v2:datakey";

    /// <summary>Binds a credential envelope to its tenant, its own row, and the DEK that sealed it.</summary>
    public static byte[] ForCredential(Guid tenantId, Guid credentialId, Guid dataKeyId) =>
        Encoding.UTF8.GetBytes($"{CredentialDomain}|{tenantId:N}|{credentialId:N}|{dataKeyId:N}");

    /// <summary>
    /// Binds a wrapped DEK to its tenant and its own row. Deliberately excludes <c>key_id</c>:
    /// rotation rewrites it (<c>KekRotationService</c>), so a binding containing it would differ
    /// between unwrap and re-wrap. The keyId already selects the KEK version, and <c>retired_at</c>
    /// is excluded for the same reason — retiring a row must never brick its unwrap.
    /// </summary>
    public static byte[] ForDataKey(Guid tenantId, Guid dataKeyId) =>
        Encoding.UTF8.GetBytes($"{DataKeyDomain}|{tenantId:N}|{dataKeyId:N}");
}
