using PatchManagement.Vault.KeyProviders;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Cold review M7: <c>VAULT_SOFTWARE_KEK_INIT</c> had no one-shot semantics, and the refusal message
/// told operators to set it — so a compose file that keeps it set turns every failed volume mount
/// into a silent fresh-KEK mint. That is CR-1 re-armed by the very switch added to prevent it, and
/// documentation cannot fix it: the operator who leaves the flag set is the one who did not read the
/// document.
///
/// <para>Initialization therefore needs two independent signals — the flag, and an arming sentinel
/// beside the store — and consumes the second. A lost mount takes the sentinel with it, so the
/// refusal happens on exactly the occasion that matters.</para>
/// </summary>
public sealed class KekInitArmingTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    [Fact]
    public async Task The_flag_alone_does_not_initialize_an_absent_store()
    {
        // The failure this reproduces: the flag is set (a compose file nobody edited) and the store
        // is gone (the volume did not mount). Before M7 this minted a new KEK and every existing
        // credential became unrecoverable, silently.
        var dir = NewBareDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            var provider = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => provider.GetCurrentKeyIdAsync(Ct));

            Assert.Contains("REFUSED", ex.Message, StringComparison.Ordinal);
            Assert.Contains(".init", ex.Message, StringComparison.Ordinal);
            Assert.False(File.Exists(path), "a refused initialization still wrote a key file");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Arming_authorises_exactly_one_initialization()
    {
        var dir = KekScratch.NewArmedDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");

            var first = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));
            var keyId = await first.GetCurrentKeyIdAsync(Ct);
            Assert.False(string.IsNullOrWhiteSpace(keyId));
            Assert.False(KekScratch.IsArmed(path), "the sentinel survived a successful initialization");

            // Now simulate the mount coming back empty — the store is gone, the flag is still set,
            // and this is the moment CR-1 fires. It must refuse, because the arming was consumed.
            File.Delete(path);
            var second = new SoftwareKeyProvider(new KeyFileKekSource(path, allowInitialize: true));

            await Assert.ThrowsAsync<InvalidOperationException>(() => second.GetCurrentKeyIdAsync(Ct));
            Assert.False(File.Exists(path), "a second cold start re-minted the store");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task The_refusal_tells_an_operator_what_to_do_and_what_not_to_do()
    {
        // A refusal an operator cannot act on gets worked around, and the workaround here destroys
        // the estate. Both halves must be present: how to proceed, and why usually not to.
        var dir = NewBareDirectory();
        try
        {
            var path = Path.Combine(dir, "kek.json");
            var provider = new SoftwareKeyProvider(new KeyFileKekSource(path));

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => provider.GetCurrentKeyIdAsync(Ct));

            Assert.Contains(Path.GetFullPath(path), ex.Message, StringComparison.Ordinal);
            Assert.Contains("VAULT_SOFTWARE_KEK_INIT", ex.Message, StringComparison.Ordinal);
            Assert.Contains("REMOVE THE VARIABLE AGAIN", ex.Message, StringComparison.Ordinal);
            Assert.Contains("unrecoverable", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>A scratch directory deliberately left UNARMED.</summary>
    private static string NewBareDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "kek-bare-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(dir);
        return dir;
    }
}
