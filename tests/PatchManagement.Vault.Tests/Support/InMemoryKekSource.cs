using PatchManagement.Vault.KeyProviders;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// A test <see cref="IKekSource"/> that keeps the keyset in memory. Lets unit/integration tests
/// exercise wrap/unwrap/rotation without touching the filesystem. <see cref="KeyFileKekSource"/>
/// gets its own dedicated round-trip and durability tests for the on-disk path.
/// </summary>
public sealed class InMemoryKekSource : IKekSource
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private KekKeyset _keyset = KekKeyset.CreateNew();

    public Task<KekKeyset> LoadAsync(CancellationToken ct) => Task.FromResult(_keyset);

    /// <summary>Serialized like the real source, so concurrent callers cannot lose a version.</summary>
    public async Task<KekKeyset> AddVersionAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            _keyset = _keyset.WithNewVersion();
            return _keyset;
        }
        finally
        {
            _gate.Release();
        }
    }

    public string Describe() => "in-memory";
}
