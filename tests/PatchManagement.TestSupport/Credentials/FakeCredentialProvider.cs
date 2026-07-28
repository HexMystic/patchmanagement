using System.Text;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.TestSupport.Credentials;

/// <summary>
/// In-memory <see cref="ICredentialProvider"/> so the connector suite runs with no Phase 2 vault
/// present — an explicit exit criterion of <c>docs/phases/phase-3.md</c>, not a convenience.
///
/// <para><b>Why every resolve allocates.</b> <see cref="ResolvedCredential"/>'s constructor
/// <em>aliases</em> the array it is handed and <c>Dispose</c> zeroes it in place. A fake that cached
/// one array and returned it twice would hand out a buffer of zeros the second time, and the
/// resulting failure would look like an auth bug rather than a test-double bug. So the material is
/// held as a factory and a fresh copy is minted per call.</para>
/// </summary>
public sealed class FakeCredentialProvider : ICredentialProvider
{
    private readonly Dictionary<Guid, Entry> _entries = new();

    private sealed record Entry(Func<byte[]> Material, CredentialKind Kind, string? Username);

    /// <summary>Registers material for a reference. <paramref name="material"/> is invoked per resolve.</summary>
    public FakeCredentialProvider Add(
        CredentialRef reference, Func<byte[]> material, CredentialKind kind, string? username = null)
    {
        _entries[reference.Id] = new Entry(material, kind, username);
        return this;
    }

    /// <summary>Registers fixed bytes; copied on every resolve so the caller may zero them freely.</summary>
    public FakeCredentialProvider Add(
        CredentialRef reference, byte[] material, CredentialKind kind, string? username = null) =>
        Add(reference, () => material.ToArray(), kind, username);

    /// <summary>Registers a UTF-8 string as the secret — for password-shaped material (e.g. sudo).</summary>
    public FakeCredentialProvider AddSecret(
        CredentialRef reference, string secret, CredentialKind kind, string? username = null) =>
        Add(reference, () => Encoding.UTF8.GetBytes(secret), kind, username);

    /// <summary>
    /// Registers the lab fleet's ed25519 private key, read fresh from disk per resolve.
    /// Fails loudly and actionably: an absent key means the worktree was created outside the
    /// tooling that propagates <c>lab/keys/</c>, which is not a thing to diagnose from a
    /// <c>FileNotFoundException</c> thrown three layers down inside SSH.NET.
    /// </summary>
    public FakeCredentialProvider AddLabKey(CredentialRef reference, string username = "labadmin")
    {
        var path = RepoPaths.LabPrivateKey();
        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"Lab private key not found at '{path}'. Generate it with scripts/lab-keygen.ps1, " +
                "or recreate this worktree so .worktreeinclude copies lab/keys/ into it.");
        }

        return Add(reference, () => File.ReadAllBytes(path), CredentialKind.SshKey, username);
    }

    /// <summary>
    /// Registers a unique sentinel as the secret and returns it, for never-log sweeps. The value is
    /// random per call so a leak cannot be masked by a stale match from an earlier run.
    /// </summary>
    public byte[] AddSentinel(
        CredentialRef reference, CredentialKind kind = CredentialKind.SshKey, string? username = "labadmin")
    {
        var sentinel = Encoding.UTF8.GetBytes("NEVERLOG-" + Guid.NewGuid().ToString("N"));
        Add(reference, () => sentinel.ToArray(), kind, username);
        return sentinel;
    }

    public Task<ResolvedCredential> ResolveAsync(CredentialRef reference, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (!_entries.TryGetValue(reference.Id, out var entry))
            throw new KeyNotFoundException($"No fake credential registered for {reference}.");

        // Fresh array per resolve — see the class remarks.
        return Task.FromResult(new ResolvedCredential(entry.Kind, entry.Material(), entry.Username));
    }
}
