using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Rotation over a REAL on-disk key file, in an isolated database.
///
/// <para>Every other rotation test substitutes an in-memory key source, so the interaction between
/// <c>KeyFileKekSource</c> and the tenant sweep was entirely untested — the gap that let review CR-1
/// through. This closes it. The dedicated database is what allows <c>Complete</c> to be asserted
/// honestly: a sweep visits every tenant in its database, so sharing one would drag in other
/// classes' DEKs sealed under a different keyset.</para>
/// </summary>
[Collection(KeyFileVaultCollection.Name)]
public sealed class KeyFileRotationTests(KeyFileVaultFixture fx)
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly Guid TenantA = Guid.NewGuid();
    private readonly Guid TenantB = Guid.NewGuid();

    [Fact]
    public async Task Rotation_converges_every_tenant_over_a_real_key_file()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        await harness.SeedTenantAsync(TenantB, "B");

        var secretA = await StoreAsync(harness, TenantA);
        var secretB = await StoreAsync(harness, TenantB);

        var before = await DekKeyIdsAsync(harness);
        Assert.Equal(2, before.Count);

        KekRotationResult result;
        using (var provider = harness.HostLikeContainer())
            result = await provider.GetRequiredService<IKekRotationService>().RotateAsync(Ct);

        // Isolated database, so Complete is meaningful here — unlike the shared-fixture tests.
        Assert.True(result.Complete,
            $"partial: {result.Failures.Count} DEK, {result.TenantFailures.Count} tenant failure(s)");

        var after = await DekKeyIdsAsync(harness);
        Assert.Equal(result.KeyId, after[TenantA]);
        Assert.Equal(result.KeyId, after[TenantB]);
        Assert.NotEqual(before[TenantA], after[TenantA]);

        // The key file is the only durable copy: a fresh provider reading it must still unwrap.
        await AssertResolvesAsync(harness, TenantA, secretA);
        await AssertResolvesAsync(harness, TenantB, secretB);
    }

    private static async Task<byte[]> StoreAsync(VaultTestHarness harness, Guid tenantId)
    {
        var secret = Encoding.UTF8.GetBytes("keyfile-" + Guid.NewGuid());
        await using var db = harness.AppContext(tenantId);
        await harness.Provider(db, tenantId).StoreAsync(
            new StoreCredentialRequest("kf", CredentialKind.SshKey, secret), Ct);
        return secret;
    }

    private static async Task AssertResolvesAsync(VaultTestHarness harness, Guid tenantId, byte[] expected)
    {
        await using var db = harness.AppContext(tenantId);
        var id = await db.Credentials.Where(c => c.TenantId == tenantId).Select(c => c.Id).FirstAsync();
        using var resolved = await harness.Provider(db, tenantId).ResolveAsync(new CredentialRef(id), Ct);
        Assert.Equal(expected, resolved.Secret.ToArray());
    }

    private async Task<Dictionary<Guid, string?>> DekKeyIdsAsync(VaultTestHarness harness)
    {
        await using var owner = harness.OwnerContext();
        return await owner.DataKeys
            .Where(k => k.TenantId == TenantA || k.TenantId == TenantB)
            .ToDictionaryAsync(k => k.TenantId, k => k.KeyId);
    }
}
