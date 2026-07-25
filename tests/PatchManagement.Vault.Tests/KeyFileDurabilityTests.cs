using System.Security.Cryptography;
using PatchManagement.Vault.KeyProviders;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Review findings C2, C3 and C4 — the three data-loss defects in KEK file custody. Each asserts
/// OBSERVED state (CLAUDE.md §6): the bytes on disk, and what a FRESH source reading them back can
/// still unwrap — never merely that a call returned without throwing.
/// </summary>
public sealed class KeyFileDurabilityTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private static KeyBinding Binding() => new(Guid.NewGuid(), Guid.NewGuid());

    /// <summary>
    /// C4 (the current key must not advance past what is durably stored) and C3 (a failed write must
    /// not cost the existing versions), proven together on one failure.
    /// </summary>
    [Fact]
    public async Task A_failed_write_neither_advances_the_current_key_nor_loses_existing_keys()
    {
        var dir = NewScratchDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            var provider = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));

            var originalKeyId = await provider.GetCurrentKeyIdAsync(Ct); // first boot writes the file
            var dek = RandomNumberGenerator.GetBytes(32);
            var binding = Binding();
            var wrapped = await provider.WrapAsync(dek, originalKeyId, binding, Ct);
            var fileBefore = await File.ReadAllBytesAsync(path, Ct);

            // Occupy the temp path with a directory so the write fails deterministically, mid-rotation.
            Directory.CreateDirectory(path + ".tmp");

            await Assert.ThrowsAnyAsync<Exception>(() => provider.RotateMasterKeyAsync(Ct));

            // C4: nothing may be wrapped under a version that never reached disk.
            Assert.Equal(originalKeyId, await provider.GetCurrentKeyIdAsync(Ct));

            // C3: the only durable copy of the KEK is untouched, and still yields every version.
            Assert.Equal(fileBefore, await File.ReadAllBytesAsync(path, Ct));

            var restarted = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            Assert.Equal(originalKeyId, await restarted.GetCurrentKeyIdAsync(Ct));
            Assert.Equal(dek, await restarted.UnwrapAsync(wrapped, originalKeyId, binding, Ct));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// C2: two instances sharing one key file must not erase each other's KEK versions. Two
    /// independent source+provider pairs share nothing but the file — the two-process condition
    /// minus the process boundary — and a real OS file lock is per-handle, so it is genuinely
    /// exercised here.
    /// </summary>
    [Fact]
    public async Task Concurrent_rotations_do_not_erase_each_others_key_versions()
    {
        var dir = NewScratchDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            var originalKeyId = await new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true))
                .GetCurrentKeyIdAsync(Ct);

            var a = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            var b = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));

            var minted = await Task.WhenAll(a.RotateMasterKeyAsync(Ct), b.RotateMasterKeyAsync(Ct));

            // Every version — the original and both freshly minted — must still be usable by a
            // process that knows only what is on disk.
            var restarted = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            foreach (var keyId in minted.Append(originalKeyId))
            {
                var dek = RandomNumberGenerator.GetBytes(32);
                var binding = Binding();
                var wrapped = await restarted.WrapAsync(dek, keyId, binding, Ct);
                Assert.Equal(dek, await restarted.UnwrapAsync(wrapped, keyId, binding, Ct));
            }

            // The write path must not leave key material lying around in a temp file.
            Assert.False(File.Exists(path + ".tmp"), "a temp key file was left behind");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// C2, second half: caching the keyset for the process lifetime meant a version another process
    /// minted was unknown until restart — a hard outage, not just a stale read.
    /// </summary>
    [Fact]
    public async Task A_version_minted_by_another_instance_is_usable_without_a_restart()
    {
        var dir = NewScratchDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            var a = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            var b = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));

            await a.GetCurrentKeyIdAsync(Ct); // A loads and caches the keyset as it stands

            // B then mints a version A has never seen, and wraps under it.
            var mintedByB = await b.RotateMasterKeyAsync(Ct);
            var dek = RandomNumberGenerator.GetBytes(32);
            var binding = Binding();
            var wrappedByB = await b.WrapAsync(dek, mintedByB, binding, Ct);

            // A must reload on the miss rather than failing with "No KEK version ... is loaded".
            Assert.Equal(dek, await a.UnwrapAsync(wrappedByB, mintedByB, binding, Ct));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>Per-test scratch directory: the design also produces a lock sidecar, so deleting a
    /// single file would leak.</summary>
    private static string NewScratchDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "kek-test-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(dir);
        return dir;
    }
}
