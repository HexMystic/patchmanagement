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
    // Instance (not static) so each method gets its own tenant: with a shared collection-fixture DB
    // and a fresh per-method KEK keyset, a shared tenant would let one method read a DEK another
    // wrapped under a different keyset. See VaultRoundTripTests for the detail.
    private readonly Guid Tenant = Guid.NewGuid();

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

    /// <summary>
    /// The ERROR path must leak nothing either (companion to the happy-path scan above). A real
    /// credential is stored so a genuine secret is in the tenant's vault, then we resolve a
    /// DIFFERENT, non-existent id to drive the not-found branch — which emits a warning log and
    /// throws <see cref="KeyNotFoundException"/>. We scan BOTH the captured log body AND the thrown
    /// exception object (message + stack) for the secret in every encoding. Asserts the invariant on
    /// the error path rather than resting on code inspection.
    /// </summary>
    [Fact]
    public async Task No_secret_material_leaks_on_the_not_found_error_path()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(Tenant, "T");

        var secret = Encoding.UTF8.GetBytes("NEVERLOG-ERR-" + Guid.NewGuid().ToString("N"));
        const string username = "domain-admin";
        using var capturing = new CapturingLoggerProvider();

        await using var db = harness.AppContext(Tenant);

        // A real secret genuinely lives in this tenant's vault (stored via a separate logger, so the
        // capturing logger below sees ONLY the error path).
        await harness.Provider(db, Tenant).StoreAsync(
            new StoreCredentialRequest("present", CredentialKind.WindowsPassword, secret, username),
            CancellationToken.None);

        // Drive the not-found branch: resolve an id that does not exist for this tenant.
        var vault = harness.Provider(db, Tenant, capturing.CreateLogger<VaultCredentialProvider>());
        var missing = new CredentialRef(Guid.NewGuid());
        var ex = await Assert.ThrowsAsync<KeyNotFoundException>(
            () => vault.ResolveAsync(missing, CancellationToken.None));

        // Scan the emitted warning AND the exception object (message + stack) together.
        var errorBody = capturing.AllText + "\n" + ex;
        Assert.NotEqual(string.Empty, capturing.AllText); // sanity: the error branch DID log (a warning)

        Assert.DoesNotContain(Encoding.UTF8.GetString(secret), errorBody);
        Assert.DoesNotContain(Convert.ToBase64String(secret), errorBody);
        Assert.DoesNotContain(Convert.ToHexString(secret), errorBody);
        Assert.DoesNotContain(Convert.ToHexString(secret).ToLowerInvariant(), errorBody);
    }
}
