using System.Text;
using Microsoft.EntityFrameworkCore;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// The invariant reviewers probe first (phase-2.md): rotating the master KEK re-wraps every DEK
/// under the new version but NEVER re-encrypts a credential. Proven by capturing the envelope bytes
/// and DEK before and after rotation, then resolving to confirm the secret still decrypts.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class KekRotationTests(PostgresFixture fx)
{
    // Instance (not static) — one tenant set per method, so a DEK is never shared across methods
    // whose harnesses hold different in-memory KEK keysets. See VaultRoundTripTests for the detail.
    private readonly Guid TenantA = Guid.NewGuid();
    private readonly Guid TenantB = Guid.NewGuid();

    [Fact]
    public async Task Rotation_rewraps_deks_without_reencrypting_credentials()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        await harness.SeedTenantAsync(TenantB, "B");

        var secretA = Encoding.UTF8.GetBytes("rot-A-" + Guid.NewGuid());
        var secretB = Encoding.UTF8.GetBytes("rot-B-" + Guid.NewGuid());

        CredentialRef refA, refB;
        await using (var db = harness.AppContext(TenantA))
            refA = await harness.Provider(db, TenantA).StoreAsync(
                new StoreCredentialRequest("a", CredentialKind.SshKey, secretA, "root"), CancellationToken.None);
        await using (var db = harness.AppContext(TenantB))
            refB = await harness.Provider(db, TenantB).StoreAsync(
                new StoreCredentialRequest("b", CredentialKind.WindowsPassword, secretB, "admin"), CancellationToken.None);

        // Snapshot BEFORE: credential envelopes + DEK wrapped material and key ids.
        var (envelopesBefore, deksBefore) = await SnapshotAsync(harness);
        var oldKeyId = await harness.KeyProvider.GetCurrentKeyIdAsync(CancellationToken.None);

        // Rotate (cross-tenant, owner context).
        KekRotationResult result;
        await using (var owner = harness.OwnerContext())
            result = await harness.Rotation(owner).RotateAsync(CancellationToken.None);

        var (envelopesAfter, deksAfter) = await SnapshotAsync(harness);

        // 1. A new KEK version, all DEKs re-wrapped, ZERO credentials re-encrypted.
        Assert.NotEqual(oldKeyId, result.NewKeyId);
        Assert.Equal(0, result.CredentialsReencrypted);
        Assert.True(result.DeksRewrapped >= 2);

        // 2. Credential envelopes are byte-for-byte UNCHANGED.
        foreach (var (id, before) in envelopesBefore)
            Assert.Equal(before, envelopesAfter[id]);

        // 3. Every DEK now carries the new key id and different wrapped bytes.
        foreach (var (id, before) in deksBefore)
        {
            Assert.Equal(result.NewKeyId, deksAfter[id].KeyId);
            Assert.NotEqual(oldKeyId, deksAfter[id].KeyId);
            Assert.False(before.Wrapped.SequenceEqual(deksAfter[id].Wrapped),
                "the wrapped DEK bytes must change after a re-wrap");
        }

        // 4. Credentials still resolve to the original secrets after rotation.
        await using (var db = harness.AppContext(TenantA))
        {
            using var r = await harness.Provider(db, TenantA).ResolveAsync(refA, CancellationToken.None);
            Assert.Equal(secretA, r.Secret.ToArray());
        }
        await using (var db = harness.AppContext(TenantB))
        {
            using var r = await harness.Provider(db, TenantB).ResolveAsync(refB, CancellationToken.None);
            Assert.Equal(secretB, r.Secret.ToArray());
        }
    }

    private static async Task<(Dictionary<Guid, byte[]> Envelopes, Dictionary<Guid, (string? KeyId, byte[] Wrapped)> Deks)>
        SnapshotAsync(VaultTestHarness harness)
    {
        await using var owner = harness.OwnerContext();
        var envelopes = await owner.Credentials
            .Where(c => c.Envelope != null)
            .ToDictionaryAsync(c => c.Id, c => c.Envelope!);
        var deks = await owner.DataKeys
            .Where(k => k.WrappedDek != null)
            .ToDictionaryAsync(k => k.Id, k => (k.KeyId, k.WrappedDek!));
        return (envelopes, deks);
    }
}
