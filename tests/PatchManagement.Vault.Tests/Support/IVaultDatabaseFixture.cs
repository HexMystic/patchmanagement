using PatchManagement.Vault.KeyProviders;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// What <see cref="VaultTestHarness"/> needs from a database fixture: the two role connections and
/// the key provider whose keyset every DEK in that database is sealed under.
///
/// <para>The abstraction exists because a rotation sweep visits EVERY tenant in its database, so a
/// test wanting a DIFFERENT key provider — a real <see cref="KeyFileKekSource"/>, say — must also
/// have its own database, or it would meet other test classes' DEKs wrapped under a keyset it has
/// never loaded.</para>
/// </summary>
public interface IVaultDatabaseFixture
{
    /// <summary>Owner connection — bypasses RLS. Seeding and raw inspection only.</summary>
    string OwnerConnectionString { get; }

    /// <summary>Restricted app-role connection — RLS enforced. The production path.</summary>
    string AppConnectionString { get; }

    /// <summary>The provider every DEK in this database is sealed under.</summary>
    IKeyProvider SharedKeyProvider { get; }
}
