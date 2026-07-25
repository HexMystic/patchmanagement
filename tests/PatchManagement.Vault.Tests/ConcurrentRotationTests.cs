using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Cold-review H2: two rotations running at once must not leave the estate on a superseded KEK.
///
/// <para>ADR 0016 deferred this as multi-process-only. That premise was wrong — <b>one</b> process is
/// enough. <c>IKekRotationService</c> is a singleton with no sweep-level guard, so two callers
/// interleave like this: A mints k1, B mints k2, and A's sweep — still running — converges the whole
/// estate onto k1, which is by then superseded. After a breach that silently restores the compromised
/// key, and both rotations report success.</para>
///
/// <para>The interleave is forced rather than raced for, via <see cref="StallingKeyProvider"/>: a
/// concurrency test that depends on timing proves nothing on the run where the timing happens to be
/// kind.</para>
/// </summary>
[Collection(KeyFileVaultCollection.Name)]
public sealed class ConcurrentRotationTests(KeyFileVaultFixture fx)
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly Guid TenantA = Guid.NewGuid();
    private readonly Guid TenantB = Guid.NewGuid();

    [Fact]
    public async Task Two_concurrent_rotations_never_leave_the_estate_on_a_superseded_key()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "concurrent-A");
        await harness.SeedTenantAsync(TenantB, "concurrent-B");
        await StoreAsync(harness, TenantA);
        await StoreAsync(harness, TenantB);

        var stalling = new StallingKeyProvider(harness.KeyProvider);
        using var provider = harness.HostLikeContainer(keyProvider: stalling);

        // ONE service instance, resolved once: the guard being tested lives on the singleton, so two
        // containers would each get their own and prove nothing.
        var rotation = provider.GetRequiredService<IKekRotationService>();

        var first = Task.Run(() => rotation.RotateAsync(Ct), Ct);

        // Only start the second once the first is parked mid-sweep, holding a key id it has already
        // minted. Bounded: if the guard exists, the first never reaches the sweep until it owns the
        // rotation outright, and this simply falls through.
        await Task.WhenAny(stalling.Stalled, Task.Delay(TimeSpan.FromSeconds(5), Ct));

        var second = Task.Run(() => rotation.RotateAsync(Ct), Ct);

        // Let the second finish if it can. Post-fix it cannot — it is queued behind the first — so
        // this yields on the timeout instead of deadlocking.
        await Task.WhenAny(second, Task.Delay(TimeSpan.FromSeconds(3), Ct));
        stalling.Release();

        var results = await Task.WhenAll(first, second);

        // The verdict. Whichever rotation finished last, no DEK may be left on a version that is no
        // longer current: that is the estate re-pinned backwards onto a potentially compromised key.
        var current = await harness.KeyProvider.RefreshCurrentKeyIdAsync(Ct);
        var stranded = await StrandedDeksAsync(harness, current);

        Assert.True(
            stranded.Count == 0,
            $"after two concurrent rotations, {stranded.Count} DEK(s) sit on a superseded KEK while "
            + $"the current version is '{current}': {string.Join(", ", stranded)}");

        // Both genuinely ran — serialised, not one silently discarded. If the guard ever becomes
        // "refuse the second caller" this fails, which is the right outcome for a change that would
        // otherwise make this test quietly vacuous.
        Assert.Equal(2, results.Select(r => r.KeyId).Distinct().Count());

        // Whichever ran last owns the estate, and must have told the truth about it. The other one
        // is not required to match: it converged everything onto its own key while it held the
        // rotation, and was then legitimately superseded — that is serialisation working, not a lie.
        var last = Assert.Single(results, r => r.KeyId == current);
        Assert.True(last.Complete, "the rotation that ran last did not converge the estate it reports on");
    }

    private static async Task StoreAsync(VaultTestHarness harness, Guid tenantId)
    {
        var secret = Encoding.UTF8.GetBytes("concurrent-" + Guid.NewGuid());
        await using var db = harness.AppContext(tenantId);
        await harness.Provider(db, tenantId).StoreAsync(
            new StoreCredentialRequest("cc", CredentialKind.SshKey, secret), Ct);
    }

    private static async Task<List<string>> StrandedDeksAsync(VaultTestHarness harness, string current)
    {
        await using var owner = harness.OwnerContext();
        return await owner.DataKeys
            .Where(k => k.RetiredAt == null && k.WrappedDek != null && k.KeyId != current)
            .Select(k => k.Id.ToString() + " on " + k.KeyId)
            .ToListAsync();
    }
}
