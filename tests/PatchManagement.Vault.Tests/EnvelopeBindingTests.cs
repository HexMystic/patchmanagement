using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Persistence.Entities;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Review finding H1: an adversary with DB write access relocates a sealed envelope into another
/// tenant's rows. RLS and the composite FK are both satisfied, so the application itself becomes the
/// decryption oracle. These prove the envelope is cryptographically bound to the row it sits in.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class EnvelopeBindingTests(PostgresFixture fx)
{
    // Instance, not static — each method needs its own tenants because each harness holds its own
    // in-memory KEK keyset. See VaultRoundTripTests for the detail.
    private readonly Guid TenantA = Guid.NewGuid();
    private readonly Guid TenantB = Guid.NewGuid();

    [Fact]
    public async Task Relocated_envelope_cannot_be_decrypted_by_the_receiving_tenant()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        await harness.SeedTenantAsync(TenantB, "B");

        var secretA = Encoding.UTF8.GetBytes("victim-secret-" + Guid.NewGuid());

        CredentialRef refA;
        await using (var db = harness.AppContext(TenantA))
        {
            refA = await harness.Provider(db, TenantA).StoreAsync(
                new StoreCredentialRequest("victim", CredentialKind.WindowsPassword, secretA, "administrator"),
                CancellationToken.None);
        }

        // The attack: copy tenant A's wrapped DEK and sealed envelope into fresh rows owned by
        // tenant B. Both carry tenant_id = B, so RLS and the composite FK accept them. Inserted DEK
        // first so the (tenant_id, data_key_id) FK is satisfied at every statement.
        var stolenId = Guid.NewGuid();
        var clonedDekId = Guid.NewGuid();
        await using (var owner = harness.OwnerContext())
        {
            var srcCred = await owner.Credentials.SingleAsync(c => c.Id == refA.Id);
            var srcDek = await owner.DataKeys.SingleAsync(k => k.Id == srcCred.DataKeyId);
            var now = DateTimeOffset.UtcNow;

            owner.DataKeys.Add(new DataKey
            {
                Id = clonedDekId,
                TenantId = TenantB,
                WrappedDek = srcDek.WrappedDek,
                KeyId = srcDek.KeyId,
                CreatedAt = now,
            });
            await owner.SaveChangesAsync();

            owner.Credentials.Add(new Credential
            {
                Id = stolenId,
                TenantId = TenantB,
                Name = "stolen",
                Kind = srcCred.Kind,
                Envelope = srcCred.Envelope,
                DataKeyId = clonedDekId,
                CreatedAt = now,
                UpdatedAt = now,
            });
            await owner.SaveChangesAsync();
        }

        await using (var db = harness.AppContext(TenantB))
        {
            var vault = harness.Provider(db, TenantB);

            // The relocated rows are cryptographically bound to tenant A's identity, so the DEK
            // fails to unwrap under tenant B's row binding. Asserting the tag-mismatch subclass
            // specifically: a bare CryptographicException is also raised for a malformed or
            // wrong-version blob, so the looser assertion could pass without the binding being what
            // rejected it.
            await Assert.ThrowsAnyAsync<AuthenticationTagMismatchException>(
                () => vault.ResolveAsync(new CredentialRef(stolenId), CancellationToken.None));
        }

        // Remove the planted rows. The cloned data_keys row is permanently unwrappable by design,
        // and KEK rotation re-wraps EVERY non-retired DEK in this shared database — leaving it would
        // hand the rotation test a landmine. (That rotation aborts on one poisoned row is real
        // behaviour, not a test artefact: worth noting against the review's rotation-robustness
        // findings, but out of scope here.)
        await using (var owner = harness.OwnerContext())
        {
            await owner.Credentials.Where(c => c.Id == stolenId).ExecuteDeleteAsync();
            await owner.DataKeys.Where(k => k.Id == clonedDekId).ExecuteDeleteAsync();
        }
    }

    /// <summary>
    /// The credential-layer half of the binding. The relocation test above is caught by the DEK
    /// layer (unwrap runs first), so only this exercises the credential-id binding — and it covers a
    /// real intra-tenant escalation that has no foreign-key mitigation at all: same tenant, same
    /// DEK, one credential's envelope pasted onto another's row.
    /// </summary>
    [Fact]
    public async Task Envelope_swapped_onto_another_row_in_the_same_tenant_cannot_be_decrypted()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");

        var privileged = Encoding.UTF8.GetBytes("domain-admin-secret-" + Guid.NewGuid());

        CredentialRef high, low;
        await using (var db = harness.AppContext(TenantA))
        {
            var vault = harness.Provider(db, TenantA);
            high = await vault.StoreAsync(
                new StoreCredentialRequest("high", CredentialKind.WindowsPassword, privileged, "administrator"),
                CancellationToken.None);
            low = await vault.StoreAsync(
                new StoreCredentialRequest("low", CredentialKind.WindowsPassword,
                    Encoding.UTF8.GetBytes("ordinary"), "guest"),
                CancellationToken.None);
        }

        // Both rows belong to the same tenant and share one DEK, so nothing but the envelope's own
        // binding distinguishes them.
        await using (var owner = harness.OwnerContext())
        {
            var highRow = await owner.Credentials.SingleAsync(c => c.Id == high.Id);
            var lowRow = await owner.Credentials.SingleAsync(c => c.Id == low.Id);
            Assert.Equal(highRow.DataKeyId, lowRow.DataKeyId); // same DEK — the swap is otherwise valid

            lowRow.Envelope = highRow.Envelope;
            await owner.SaveChangesAsync();
        }

        await using (var db = harness.AppContext(TenantA))
        {
            var vault = harness.Provider(db, TenantA);
            await Assert.ThrowsAnyAsync<AuthenticationTagMismatchException>(
                () => vault.ResolveAsync(low, CancellationToken.None));
        }
    }
}
