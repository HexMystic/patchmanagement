namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// Scratch key-file plumbing shared by the key-custody suites.
///
/// <para><see cref="Arm"/> exists because cold-start initialization needs two independent signals
/// since cold review M7: the <c>allowInitialize</c> opt-in AND an arming sentinel beside the store,
/// which the source deletes once it has written. Tests that legitimately first-boot a store call it;
/// tests that assert a refusal deliberately do not.</para>
/// </summary>
public static class KekScratch
{
    /// <summary>A fresh scratch directory, already armed for one initialization.</summary>
    public static string NewArmedDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "kek-test-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(dir);
        Arm(Path.Combine(dir, "kek.json"));
        return dir;
    }

    /// <summary>
    /// Authorises exactly one initialization of the store at <paramref name="keyPath"/>. Harmless if
    /// the store already exists — the sentinel is only consulted when it does not.
    /// </summary>
    public static void Arm(string keyPath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(keyPath));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        File.WriteAllBytes(keyPath + ".init", []);
    }

    /// <summary>Whether the store is still armed — false once an initialization has consumed it.</summary>
    public static bool IsArmed(string keyPath) => File.Exists(keyPath + ".init");
}
