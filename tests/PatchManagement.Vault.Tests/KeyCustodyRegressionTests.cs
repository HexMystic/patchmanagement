using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Contracts.Tenancy;
using PatchManagement.Vault.KeyProviders;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// The three merge-blocking findings from the Phase 2 re-review. Two of them (CR-1, C-A) are
/// regressions introduced by the remediation slice itself, and both are silent data-loss paths that
/// report success — the exact class of defect that remediation existed to remove.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class KeyCustodyRegressionTests(PostgresFixture fx)
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly Guid TenantA = Guid.NewGuid();

    /// <summary>
    /// CR-1: a rotation whose key file has vanished must fail loud. It must NOT treat absence as
    /// first boot, mint a fresh keyset, write it over the path, and report success — that discards
    /// every KEK version the process holds and bricks every DEK in the database.
    /// </summary>
    [Fact]
    public async Task Rotation_with_a_missing_key_file_fails_loud_and_writes_nothing()
    {
        var dir = NewScratchDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            // Initialization is opt-in, so this is a genuine first boot.
            var provider = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            var originalKeyId = await provider.GetCurrentKeyIdAsync(Ct);

            // The file goes away — an unmounted volume, a recreated secrets dir, a changed CWD.
            File.Delete(path);

            await Assert.ThrowsAnyAsync<Exception>(() => provider.RotateMasterKeyAsync(Ct));

            // Nothing may be minted in its place, and the process must not believe it rotated.
            Assert.False(File.Exists(path), "a rotation against a missing key file wrote a new one");
            Assert.Equal(originalKeyId, await provider.GetCurrentKeyIdAsync(Ct));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// C-A: a process whose cached keyset is stale must not converge the estate onto the key it
    /// happens to remember. Two providers share one store — the same shape as two app instances
    /// sharing a key file — and only one of them rotates.
    /// </summary>
    [Fact]
    public async Task Complete_rotation_from_a_stale_process_targets_the_current_key_not_the_stale_one()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");

        // Stale process: it loads and caches the keyset as it stands now.
        var stale = new SoftwareKeyProvider(fx.SharedKekSource);
        var keyIdBeforeRotation = await stale.GetCurrentKeyIdAsync(Ct);

        await using (var db = harness.AppContext(TenantA))
        {
            await harness.Provider(db, TenantA).StoreAsync(
                new StoreCredentialRequest("c", CredentialKind.SshKey,
                    Encoding.UTF8.GetBytes("stale-" + Guid.NewGuid())),
                Ct);
        }

        // Another process rotates. The stale provider is never told.
        var rotatedKeyId = await fx.SharedKeyProvider.RotateMasterKeyAsync(Ct);
        Assert.NotEqual(keyIdBeforeRotation, rotatedKeyId);

        KekRotationResult result;
        using (var provider = harness.HostLikeContainer(stale))
            result = await provider.GetRequiredService<IKekRotationService>().CompleteRotationAsync(Ct);

        // Converging onto keyIdBeforeRotation would re-wrap the estate back onto the superseded key.
        Assert.Equal(rotatedKeyId, result.KeyId);
    }

    /// <summary>
    /// H-A: a sweep in which whole tenants failed must not report Complete. Anything throwing
    /// outside the per-DEK try — a dropped connection, a failed save, a failed audit — is a tenant
    /// failure, and dropping those is C1's "rotation failed but reported success" one layer up.
    /// </summary>
    [Fact]
    public async Task A_tenant_level_failure_makes_the_rotation_incomplete()
    {
        var failedTenant = Guid.NewGuid();
        var sweep = new TenantSweepResult(
            TenantsTotal: 1,
            TenantsAttempted: 1,
            TenantsSucceeded: 0,
            Failures: [new TenantFailure(failedTenant, "IOException: connection reset")]);

        var rotation = new KekRotationService(
            new FakeTenantScopeFactory(sweep),
            fx.SharedKeyProvider,
            new SystemVaultActor(),
            NullLogger<KekRotationService>.Instance);

        var result = await rotation.CompleteRotationAsync(Ct);

        Assert.False(result.Complete, "a rotation that failed for a whole tenant reported success");
    }

    /// <summary>
    /// The other route into the same destruction: a cache miss reloads mid-flight, typically while
    /// unwrapping existing ciphertext. Initializing there could not possibly produce the key being
    /// sought, and would overwrite the real store on its way to failing.
    /// </summary>
    [Fact]
    public async Task Reload_on_miss_with_a_missing_key_file_fails_loud_and_writes_nothing()
    {
        var dir = NewScratchDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            var provider = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            var keyId = await provider.GetCurrentKeyIdAsync(Ct);
            var wrapped = await provider.WrapAsync(
                RandomNumberGenerator.GetBytes(32), keyId, new KeyBinding(Guid.NewGuid(), Guid.NewGuid()), Ct);

            File.Delete(path);

            // An unknown key id forces the reload path.
            await Assert.ThrowsAnyAsync<Exception>(() => provider.UnwrapAsync(
                wrapped, "kek-does-not-exist", new KeyBinding(Guid.NewGuid(), Guid.NewGuid()), Ct));

            Assert.False(File.Exists(path), "a reload against a missing key file wrote a new one");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// Cold start is the one place initialization is permissible, and even there it is opt-in: an
    /// absent store is indistinguishable from an unreachable one, and the failure is unrecoverable.
    /// </summary>
    [Fact]
    public async Task Cold_start_initializes_only_with_the_explicit_opt_in()
    {
        var dir = NewScratchDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");

            var refusing = new SoftwareKeyProvider(new KeyFileKekSource(path));
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => refusing.GetCurrentKeyIdAsync(Ct));

            Assert.Contains("VAULT_SOFTWARE_KEK_INIT", ex.Message, StringComparison.Ordinal);
            Assert.False(File.Exists(path), "a refused cold start still created a key file");

            // With the opt-in AND the arming sentinel, a genuine first boot works.
            Assert.True(KekScratch.IsArmed(path), "the scratch directory should start armed");
            var initializing = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            Assert.False(string.IsNullOrWhiteSpace(await initializing.GetCurrentKeyIdAsync(Ct)));
            Assert.True(File.Exists(path));

            // And the arming is CONSUMED — that is what makes it one-shot rather than advisory
            // (cold review M7).
            Assert.False(KekScratch.IsArmed(path), "initialization did not consume the arming sentinel");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// The sweep half of H-A: a tenant whose scope body throws is recorded as a tenant failure and
    /// the sweep reports itself incomplete.
    /// </summary>
    [Fact]
    public async Task A_throwing_sweep_body_is_recorded_as_a_tenant_failure()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");

        using var provider = harness.HostLikeContainer();
        var scopes = provider.GetRequiredService<ITenantScopeFactory>();

        var sweep = await scopes.SweepAsync(
            "test.throw", (_, _) => throw new IOException("connection reset"), Ct);

        Assert.False(sweep.Complete);
        Assert.NotEmpty(sweep.Failures);
        Assert.All(sweep.Failures, f => Assert.Contains("IOException", f.Reason, StringComparison.Ordinal));
    }

    private static string NewScratchDirectory() => KekScratch.NewArmedDirectory();
}
