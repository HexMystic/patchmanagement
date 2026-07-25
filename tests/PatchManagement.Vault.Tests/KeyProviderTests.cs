using System.Security.Cryptography;
using PatchManagement.Vault.KeyProviders;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>Unit coverage for the software key provider and its cold-start sources.</summary>
public sealed class KeyProviderTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    /// <summary>A distinct data-key row binding per call (ADR 0013).</summary>
    private static KeyBinding Binding() => new(Guid.NewGuid(), Guid.NewGuid());

    /// <summary>Per-test scratch directory: the key file now has a lock sidecar, so deleting a
    /// single file would leave it behind (ADR 0015).</summary>
    private static string NewScratchDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "kek-test-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public async Task Wrap_then_unwrap_recovers_the_dek()
    {
        var provider = new SoftwareKeyProvider(new InMemoryKekSource());
        var keyId = await provider.GetCurrentKeyIdAsync(Ct);
        var dek = RandomNumberGenerator.GetBytes(32);
        var binding = Binding();

        var wrapped = await provider.WrapAsync(dek, keyId, binding, Ct);
        var unwrapped = await provider.UnwrapAsync(wrapped, keyId, binding, Ct);

        Assert.Equal(dek, unwrapped);
        Assert.NotEqual(dek, wrapped); // stored form is ciphertext
    }

    /// <summary>
    /// A wrapped DEK copied into a different tenant's row must not unwrap — the KEK-layer half of
    /// ADR 0013. Same key, same ciphertext, different row identity.
    /// </summary>
    [Fact]
    public async Task Unwrap_with_a_different_row_binding_fails_authentication()
    {
        var provider = new SoftwareKeyProvider(new InMemoryKekSource());
        var keyId = await provider.GetCurrentKeyIdAsync(Ct);
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = await provider.WrapAsync(dek, keyId, Binding(), Ct);

        await Assert.ThrowsAnyAsync<AuthenticationTagMismatchException>(
            () => provider.UnwrapAsync(wrapped, keyId, Binding(), Ct));
    }

    [Fact]
    public async Task Rotation_changes_the_current_key_id_but_old_versions_still_unwrap()
    {
        var provider = new SoftwareKeyProvider(new InMemoryKekSource());
        var oldKeyId = await provider.GetCurrentKeyIdAsync(Ct);
        var dek = RandomNumberGenerator.GetBytes(32);
        var binding = Binding();
        var wrappedUnderOld = await provider.WrapAsync(dek, oldKeyId, binding, Ct);

        var newKeyId = await provider.RotateMasterKeyAsync(Ct);

        Assert.NotEqual(oldKeyId, newKeyId);
        Assert.Equal(newKeyId, await provider.GetCurrentKeyIdAsync(Ct));
        // Zero-downtime: a DEK wrapped under the retired KEK version still unwraps.
        Assert.Equal(dek, await provider.UnwrapAsync(wrappedUnderOld, oldKeyId, binding, Ct));
    }

    [Fact]
    public async Task Key_file_source_persists_and_reloads_the_keyset()
    {
        var dir = NewScratchDirectory();
        var path = Path.Combine(dir, "kek.json");
        try
        {
            var provider1 = new SoftwareKeyProvider(new KeyFileKekSource(path));
            var keyId = await provider1.GetCurrentKeyIdAsync(Ct); // first boot creates the file
            var dek = RandomNumberGenerator.GetBytes(32);
            var binding = Binding();
            var wrapped = await provider1.WrapAsync(dek, keyId, binding, Ct);

            Assert.True(File.Exists(path));

            // A fresh provider reading the same file (simulating a restart) unwraps what the first wrote.
            var provider2 = new SoftwareKeyProvider(new KeyFileKekSource(path));
            Assert.Equal(keyId, await provider2.GetCurrentKeyIdAsync(Ct));
            Assert.Equal(dek, await provider2.UnwrapAsync(wrapped, keyId, binding, Ct));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Key_file_survives_rotation_across_a_restart()
    {
        var dir = NewScratchDirectory();
        var path = Path.Combine(dir, "kek.json");
        try
        {
            var provider1 = new SoftwareKeyProvider(new KeyFileKekSource(path));
            await provider1.GetCurrentKeyIdAsync(Ct);
            var newKeyId = await provider1.RotateMasterKeyAsync(Ct);

            var provider2 = new SoftwareKeyProvider(new KeyFileKekSource(path));
            Assert.Equal(newKeyId, await provider2.GetCurrentKeyIdAsync(Ct));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Cloud_providers_are_honest_stubs()
    {
        await Assert.ThrowsAsync<NotImplementedException>(() => new AzureKeyVaultKeyProvider().GetCurrentKeyIdAsync(Ct));
        await Assert.ThrowsAsync<NotImplementedException>(() => new AwsKmsKeyProvider().GetCurrentKeyIdAsync(Ct));
        await Assert.ThrowsAsync<NotImplementedException>(() => new HashiCorpVaultKeyProvider().GetCurrentKeyIdAsync(Ct));
    }
}
