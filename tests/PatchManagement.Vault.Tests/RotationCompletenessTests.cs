using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Cold-review H1: <c>Complete</c> must mean every live DEK converged.
///
/// <para><c>data_keys.wrapped_dek</c> is nullable, and a DEK with no wrapped material is counted as
/// <c>DeksSkipped</c> and passed over. That count fed no part of <c>Complete</c>, so a DB-write
/// adversary could NULL chosen rows, let the rotation report success, and restore the original
/// <c>(wrapped_dek, key_id)</c> afterwards — leaving those credentials under the compromised KEK,
/// which stays usable because superseded versions are retained. The operator, told the rotation
/// completed, does not re-run it. The adversary chooses which credentials survive a post-breach
/// rotation.</para>
///
/// <para>This runs in the isolated key-file database, not the shared fixture. A sweep visits every
/// tenant in its database, so on the shared fixture <c>Complete == false</c> would pass for whatever
/// reason another class happened to leave behind — the assertion has to fail for THIS row or it
/// proves nothing.</para>
/// </summary>
[Collection(KeyFileVaultCollection.Name)]
public sealed class RotationCompletenessTests(KeyFileVaultFixture fx)
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly Guid Tenant = Guid.NewGuid();

    [Fact]
    public async Task A_live_dek_with_no_wrapped_material_makes_the_rotation_incomplete()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(Tenant, "h1-skipped");
        await StoreAsync(harness);

        var (dekId, original) = await ReadDekAsync(harness);
        Assert.NotNull(original); // sanity: it really was sealed before we broke it

        await SetWrappedDekAsync(harness, dekId, null);
        try
        {
            KekRotationResult result;
            using (var provider = harness.HostLikeContainer())
                result = await provider.GetRequiredService<IKekRotationService>().RotateAsync(Ct);

            // The row was not converged. Anything that says otherwise is a false success.
            Assert.False(
                result.Complete,
                $"a rotation that skipped {result.DeksSkipped} live DEK(s) reported Complete");

            Assert.True(result.DeksSkipped >= 1, "the unconvergeable DEK should have been counted as skipped");

            // Counted is not enough — it has to be nameable, or the operator cannot act on it.
            Assert.Contains(result.Failures, f => f.DataKeyId == dekId && f.TenantId == Tenant);
        }
        finally
        {
            // Same database as KeyFileRotationTests, which asserts Complete == true. Leaving a
            // permanently unconvergeable row behind would break it depending on ordering.
            await SetWrappedDekAsync(harness, dekId, original);
        }
    }

    private async Task StoreAsync(VaultTestHarness harness)
    {
        var secret = Encoding.UTF8.GetBytes("h1-" + Guid.NewGuid());
        await using var db = harness.AppContext(Tenant);
        await harness.Provider(db, Tenant).StoreAsync(
            new StoreCredentialRequest("h1", CredentialKind.SshKey, secret), Ct);
    }

    private async Task<(Guid Id, byte[]? Wrapped)> ReadDekAsync(VaultTestHarness harness)
    {
        await using var owner = harness.OwnerContext();
        var dek = await owner.DataKeys.SingleAsync(k => k.TenantId == Tenant);
        return (dek.Id, dek.WrappedDek);
    }

    private static async Task SetWrappedDekAsync(VaultTestHarness harness, Guid dekId, byte[]? wrapped)
    {
        await using var owner = harness.OwnerContext();
        var dek = await owner.DataKeys.SingleAsync(k => k.Id == dekId);
        dek.WrappedDek = wrapped;
        await owner.SaveChangesAsync();
    }
}
