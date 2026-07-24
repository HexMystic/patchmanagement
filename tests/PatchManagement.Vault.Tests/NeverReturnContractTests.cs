using System.Reflection;
using System.Text;
using System.Text.Json;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Services;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Freezes CLAUDE.md NEVER #2 as an executable contract: no vault OUTPUT type ever exposes secret
/// material. The scan reflects over the whole Vault assembly so a future DTO that grows a
/// <c>byte[]</c> secret property fails here by default.
/// </summary>
public sealed class NeverReturnContractTests
{
    /// <summary>
    /// The ONLY sanctioned raw-bytes property in the module: the plaintext secret handed IN to
    /// <see cref="StoreCredentialRequest"/>. Inputs are not responses; every other public property
    /// must be secret-free. Adding to this list is a deliberate review decision, not a test fix.
    /// </summary>
    private static readonly (Type Type, string Property)[] AllowedRawByteProperties =
        [(typeof(StoreCredentialRequest), nameof(StoreCredentialRequest.Secret))];

    [Fact]
    public void No_public_vault_type_exposes_raw_secret_bytes_via_a_property()
    {
        var offenders = new List<string>();

        foreach (var type in typeof(ICredentialVault).Assembly.GetExportedTypes())
        {
            foreach (var prop in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                if (prop.PropertyType != typeof(byte[])) continue;
                if (AllowedRawByteProperties.Any(a => a.Type == type && a.Property == prop.Name)) continue;
                offenders.Add($"{type.Name}.{prop.Name}");
            }
        }

        Assert.True(offenders.Count == 0,
            "Vault output types must not expose raw secret bytes. Offenders: " + string.Join(", ", offenders));
    }

    [Fact]
    public void The_metadata_summary_carries_only_metadata()
    {
        var props = typeof(CredentialSummary).GetProperties().Select(p => p.Name).ToArray();
        Assert.Contains(nameof(CredentialSummary.Id), props);
        Assert.Contains(nameof(CredentialSummary.Kind), props);
        Assert.DoesNotContain("Envelope", props);
        Assert.DoesNotContain("Secret", props);
        Assert.DoesNotContain("WrappedDek", props);
    }

    [Fact]
    public void Resolved_credential_cannot_be_serialized_into_its_secret()
    {
        using var cred = new ResolvedCredential(CredentialKind.WindowsPassword, Encoding.UTF8.GetBytes("hunter2"), "admin");

        // Secret is a ReadOnlySpan<byte> (a ref struct), so System.Text.Json cannot emit it — the
        // frozen contract is structurally un-serializable into its secret.
        Assert.ThrowsAny<Exception>(() => JsonSerializer.Serialize(cred));

        // And its ToString is redacted, so a stray interpolation cannot leak it either.
        var text = cred.ToString();
        Assert.Contains("<redacted>", text);
        Assert.DoesNotContain("hunter2", text);
    }
}
