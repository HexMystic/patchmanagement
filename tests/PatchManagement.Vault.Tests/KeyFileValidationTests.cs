using System.Text.Json;
using PatchManagement.Vault.KeyProviders;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Cold review L2 and L3 — the two key-file diagnostics defects. Neither is a disclosure path; both
/// cost an operator time at the exact moment they have none, which on the key-custody path is how a
/// recoverable incident becomes an unrecoverable one.
/// </summary>
public sealed class KeyFileValidationTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    // ---- L3: the store is validated on read -------------------------------------------------

    [Fact]
    public async Task A_key_of_the_wrong_length_is_rejected_when_the_store_is_read()
    {
        // Before this check the store loaded happily and the truncated key surfaced much later, from
        // CopyKeyTo, as "Destination is 32 bytes but KEK version 'x' is 16" — an error that blames
        // the caller's buffer for a corrupt file, at a call site nowhere near the cause.
        var dir = KekScratch.NewArmedDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            WriteStore(path, "kek-truncated", new byte[16]);

            var provider = new SoftwareKeyProvider(new KeyFileKekSource(path));
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => provider.GetCurrentKeyIdAsync(Ct));

            Assert.Contains("kek-truncated", ex.Message, StringComparison.Ordinal);
            Assert.Contains("16", ex.Message, StringComparison.Ordinal);
            Assert.Contains("32", ex.Message, StringComparison.Ordinal);
            Assert.Contains(path, ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Unreadable_base64_names_the_version_it_could_not_decode()
    {
        var dir = KekScratch.NewArmedDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            File.WriteAllText(path, JsonSerializer.Serialize(new
            {
                current = "kek-garbled",
                keys = new Dictionary<string, string> { ["kek-garbled"] = "this is not base64!!" },
            }));

            var provider = new SoftwareKeyProvider(new KeyFileKekSource(path));
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => provider.GetCurrentKeyIdAsync(Ct));

            Assert.Contains("kek-garbled", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task A_valid_store_still_loads()
    {
        // The guard against over-tightening: a correct 32-byte key must be unaffected.
        var dir = KekScratch.NewArmedDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            var provider = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            var minted = await provider.GetCurrentKeyIdAsync(Ct);

            var reopened = new SoftwareKeyProvider(new KeyFileKekSource(path));
            Assert.Equal(minted, await reopened.GetCurrentKeyIdAsync(Ct));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---- L2: contention is distinguished from everything else --------------------------------

    [Theory]
    [InlineData(typeof(DirectoryNotFoundException))]
    [InlineData(typeof(FileNotFoundException))]
    [InlineData(typeof(PathTooLongException))]
    public void Failures_that_retrying_cannot_fix_are_not_treated_as_contention(Type exceptionType)
    {
        var ex = (IOException)Activator.CreateInstance(exceptionType)!;
        Assert.True(KeyFileKekSource.IsDefinitelyNotContention(ex));
    }

    [Fact]
    public void A_real_sharing_violation_is_treated_as_contention()
    {
        // 0x80070020 is what Windows actually produced for a held FileShare.None handle, captured
        // from the real FileStream rather than assumed.
        var sharingViolation = new IOException("in use") { HResult = unchecked((int)0x80070020) };

        Assert.False(KeyFileKekSource.IsDefinitelyNotContention(sharingViolation));
        Assert.True(KeyFileKekSource.IsSharingViolation(sharingViolation));
    }

    [Fact]
    public void An_ordinary_io_failure_is_not_reported_as_contention()
    {
        // A full disk, say. It still gets retried — misclassifying real contention on a platform we
        // cannot test here would be the worse error — but it must not be DESCRIBED as contention.
        var diskFull = new IOException("There is not enough space on the disk.")
        {
            HResult = unchecked((int)0x80070070),
        };

        Assert.False(KeyFileKekSource.IsSharingViolation(diskFull));
        Assert.False(KeyFileKekSource.IsDefinitelyNotContention(diskFull));
    }

    [Fact]
    public async Task A_genuinely_held_lock_still_times_out_and_says_so()
    {
        var dir = KekScratch.NewArmedDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            var lockPath = path + ".lock";

            // Hold the sidecar the way a rotating process would.
            using var held = new FileStream(
                lockPath,
                new FileStreamOptions
                {
                    Mode = FileMode.OpenOrCreate,
                    Access = FileAccess.ReadWrite,
                    Share = FileShare.None,
                });

            var source = new KeyFileKekSource(
                path, allowInitialize: true, lockTimeout: TimeSpan.FromMilliseconds(300));

            var ex = await Assert.ThrowsAsync<TimeoutException>(() => source.LoadOrInitializeAsync(Ct));

            Assert.Contains(lockPath, ex.Message, StringComparison.Ordinal);
            Assert.Contains("Another process is holding it", ex.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("does NOT look like lock contention", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static void WriteStore(string path, string keyId, byte[] key) =>
        File.WriteAllText(path, JsonSerializer.Serialize(new
        {
            current = keyId,
            keys = new Dictionary<string, string> { [keyId] = Convert.ToBase64String(key) },
        }));
}
