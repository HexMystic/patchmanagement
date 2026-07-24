using PatchManagement.Vault.KeyProviders;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// A test <see cref="IKekSource"/> that keeps the keyset in memory. Lets unit/integration tests
/// exercise wrap/unwrap/rotation without touching the filesystem. <see cref="KeyFileKekSource"/>
/// gets its own dedicated round-trip test for the on-disk path.
/// </summary>
public sealed class InMemoryKekSource : IKekSource
{
    private KekKeyset _keyset = KekKeyset.CreateNew();

    public Task<KekKeyset> LoadAsync(CancellationToken ct) => Task.FromResult(_keyset);

    public Task SaveAsync(KekKeyset keyset, CancellationToken ct)
    {
        _keyset = keyset;
        return Task.CompletedTask;
    }

    public string Describe() => "in-memory";
}
