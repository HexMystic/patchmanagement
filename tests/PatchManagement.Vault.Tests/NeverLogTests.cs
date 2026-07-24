using System.Text;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// CLAUDE.md NEVER #1: no secret material appears in emitted logs at any level. We run a full
/// store + resolve through the vault with a capturing logger that records EVERY line, then scan the
/// entire captured body for the secret in every plausible encoding. If the vault ever logs a
/// secret, this fails.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class NeverLogTests(PostgresFixture fx)
{
    private static readonly Guid Tenant = Guid.NewGuid();

    [Fact]
    public async Task No_secret_material_appears_in_emitted_logs()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(Tenant, "T");

        var secret = Encoding.UTF8.GetBytes("NEVERLOG-" + Guid.NewGuid().ToString("N"));
        const string username = "domain-admin";
        using var capturing = new CapturingLoggerProvider();

        CredentialRef reference;
        await using (var db = harness.AppContext(Tenant))
        {
            var vault = harness.Provider(db, Tenant, capturing.CreateLogger<VaultCredentialProvider>());
            reference = await vault.StoreAsync(
                new StoreCredentialRequest("logged", CredentialKind.WindowsPassword, secret, username),
                CancellationToken.None);
            using var _ = await vault.ResolveAsync(reference, CancellationToken.None);
        }

        var logs = capturing.AllText;
        Assert.NotEqual(string.Empty, logs); // sanity: the vault did log SOMETHING (metadata)

        // The secret must not appear as UTF-8 text, base64, or hex.
        Assert.DoesNotContain(Encoding.UTF8.GetString(secret), logs);
        Assert.DoesNotContain(Convert.ToBase64String(secret), logs);
        Assert.DoesNotContain(Convert.ToHexString(secret), logs);
        Assert.DoesNotContain(Convert.ToHexString(secret).ToLowerInvariant(), logs);
    }
}
