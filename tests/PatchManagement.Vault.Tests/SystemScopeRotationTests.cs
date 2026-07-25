using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Contracts.Tenancy;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Entities;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Review finding C1: KEK rotation was registered against the RLS-restricted app-role context, so off
/// the HTTP path there was no tenant GUC, the DEK query returned zero rows, and it reported success
/// having rotated nothing. These exercise rotation through a container built the way the HOST builds
/// it — app-role connection, RLS interceptor, no HTTP request, no tenant context — which is exactly
/// the condition a background job runs in. See ADR 0014.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class SystemScopeRotationTests(PostgresFixture fx)
{
    // Instance, not static — one tenant pair per method. See VaultRoundTripTests.
    private readonly Guid TenantA = Guid.NewGuid();
    private readonly Guid TenantB = Guid.NewGuid();

    /// <summary>The headline: the exact path that silently no-opped before the fix.</summary>
    [Fact]
    public async Task Rotation_off_the_http_path_rotates_every_tenant()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        await harness.SeedTenantAsync(TenantB, "B");
        var secretA = await StoreCredentialAsync(harness, TenantA);
        var secretB = await StoreCredentialAsync(harness, TenantB);

        var before = await DekKeyIdsAsync(harness);
        Assert.Equal(2, before.Count); // sanity: one DEK per tenant exists to rotate

        // The background-job condition: resolved from DI, no HTTP request, no tenant set.
        KekRotationResult result;
        using (var provider = harness.HostLikeContainer())
            result = await provider.GetRequiredService<IKekRotationService>().RotateAsync(CancellationToken.None);

        var after = await DekKeyIdsAsync(harness);

        Assert.True(result.DeksRewrapped >= 2, $"expected both tenants' DEKs to move, got {result.DeksRewrapped}");
        Assert.Equal(result.KeyId, after[TenantA]);
        Assert.Equal(result.KeyId, after[TenantB]);
        Assert.NotEqual(before[TenantA], after[TenantA]);
        Assert.NotEqual(before[TenantB], after[TenantB]);

        // Both tenants audited, in their own scope.
        await using (var owner = harness.OwnerContext())
        {
            var audited = await owner.AuditLog
                .Where(a => a.Action == "kek.rotate" && (a.TenantId == TenantA || a.TenantId == TenantB))
                .Select(a => a.TenantId)
                .Distinct()
                .ToListAsync();
            Assert.Contains(TenantA, audited);
            Assert.Contains(TenantB, audited);
        }

        // And the credentials still resolve — a re-wrap never touches an envelope.
        await AssertResolvesAsync(harness, TenantA, secretA);
        await AssertResolvesAsync(harness, TenantB, secretB);
    }

    /// <summary>
    /// The guard that the privileged path did not quietly become a cross-tenant bypass: a sweep scope
    /// runs as the ordinary restricted role, with the tenant policy still enforced.
    /// </summary>
    [Fact]
    public async Task Sweep_scopes_run_as_the_restricted_role_with_rls_still_enforced()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        await harness.SeedTenantAsync(TenantB, "B");
        await StoreCredentialAsync(harness, TenantA);
        await StoreCredentialAsync(harness, TenantB);

        using var provider = harness.HostLikeContainer();
        var scopes = provider.GetRequiredService<ITenantScopeFactory>();

        using var scope = scopes.Create(TenantA);
        var db = scope.Services.GetRequiredService<AppDbContext>();

        // Not elevated: still the restricted, non-superuser, no-BYPASSRLS application role.
        var currentUser = await db.Database
            .SqlQuery<string>($"SELECT current_user AS \"Value\"")
            .SingleAsync();
        Assert.Equal("patchmgmt_app", currentUser);

        // And still fenced: the other tenant's rows are invisible from inside this scope.
        Assert.False(await db.Credentials.AnyAsync(c => c.TenantId == TenantB),
            "a sweep scope must not see another tenant's rows — RLS is still the boundary");
        Assert.True(await db.Credentials.AnyAsync(c => c.TenantId == TenantA));
    }

    /// <summary>
    /// One corrupt row must cost its own DEK, not the estate. Before the fix a single unwrap failure
    /// aborted the whole rotation.
    /// </summary>
    [Fact]
    public async Task A_poisoned_data_key_is_isolated_and_the_sweep_continues()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        await harness.SeedTenantAsync(TenantB, "B");
        await StoreCredentialAsync(harness, TenantA);
        var secretB = await StoreCredentialAsync(harness, TenantB);

        // Poison tenant A's DEK: overwrite its wrapped material with another row's, which cannot
        // authenticate under A's binding (ADR 0013).
        Guid poisonedId;
        await using (var owner = harness.OwnerContext())
        {
            var a = await owner.DataKeys.SingleAsync(k => k.TenantId == TenantA);
            var b = await owner.DataKeys.SingleAsync(k => k.TenantId == TenantB);
            poisonedId = a.Id;
            a.WrappedDek = b.WrappedDek;
            await owner.SaveChangesAsync();
        }

        KekRotationResult result;
        using (var provider = harness.HostLikeContainer())
            result = await provider.GetRequiredService<IKekRotationService>().RotateAsync(CancellationToken.None);

        // It did not throw, it reported the failure, and it kept going.
        Assert.False(result.Complete);
        Assert.Contains(result.Failures, f => f.DataKeyId == poisonedId && f.TenantId == TenantA);

        var after = await DekKeyIdsAsync(harness);
        Assert.Equal(result.KeyId, after[TenantB]);      // healthy tenant converged
        Assert.NotEqual(result.KeyId, after[TenantA]);   // poisoned tenant left behind, not corrupted
        await AssertResolvesAsync(harness, TenantB, secretB);
    }

    /// <summary>
    /// Resumability: finishing a partial rotation must converge the stragglers onto the EXISTING key
    /// rather than minting another version each attempt.
    /// </summary>
    [Fact]
    public async Task Complete_rotation_converges_stragglers_without_minting_a_new_key()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        var secretA = await StoreCredentialAsync(harness, TenantA);

        var strandedOn = (await DekKeyIdsAsync(harness))[TenantA];

        // Mint a new KEK version WITHOUT converging anything — the exact state a rotation that died
        // part-way leaves behind: a DEK validly wrapped under a real, now-superseded version.
        var newKeyId = await harness.KeyProvider.RotateMasterKeyAsync(CancellationToken.None);
        Assert.NotEqual(strandedOn, newKeyId);

        using var provider = harness.HostLikeContainer();
        var rotation = provider.GetRequiredService<IKekRotationService>();

        var currentBefore = await harness.KeyProvider.GetCurrentKeyIdAsync(CancellationToken.None);
        var result = await rotation.CompleteRotationAsync(CancellationToken.None);
        var currentAfter = await harness.KeyProvider.GetCurrentKeyIdAsync(CancellationToken.None);

        // Finishing the job must not mint another key — that is what retrying RotateAsync would do.
        Assert.Equal(currentBefore, currentAfter);
        Assert.Equal(currentBefore, result.KeyId);

        // The straggler converged onto the existing current version, and still decrypts.
        var after = await DekKeyIdsAsync(harness);
        Assert.Equal(currentBefore, after[TenantA]);
        Assert.NotEqual(strandedOn, after[TenantA]);
        await AssertResolvesAsync(harness, TenantA, secretA);
    }

    private static async Task<byte[]> StoreCredentialAsync(VaultTestHarness harness, Guid tenantId)
    {
        var secret = Encoding.UTF8.GetBytes("rotate-me-" + Guid.NewGuid());
        await using var db = harness.AppContext(tenantId);
        await harness.Provider(db, tenantId).StoreAsync(
            new StoreCredentialRequest("sys", CredentialKind.SshKey, secret), CancellationToken.None);
        return secret;
    }

    private static async Task AssertResolvesAsync(VaultTestHarness harness, Guid tenantId, byte[] expected)
    {
        await using var db = harness.AppContext(tenantId);
        var reference = await db.Credentials
            .Where(c => c.TenantId == tenantId)
            .Select(c => c.Id)
            .FirstAsync();
        using var resolved = await harness.Provider(db, tenantId)
            .ResolveAsync(new CredentialRef(reference), CancellationToken.None);
        Assert.Equal(expected, resolved.Secret.ToArray());
    }

    /// <summary>Current KEK version per tenant, for this test's tenants only (the database is shared).</summary>
    private async Task<Dictionary<Guid, string?>> DekKeyIdsAsync(VaultTestHarness harness)
    {
        await using var owner = harness.OwnerContext();
        return await owner.DataKeys
            .Where(k => k.TenantId == TenantA || k.TenantId == TenantB)
            .ToDictionaryAsync(k => k.TenantId, k => k.KeyId);
    }
}
