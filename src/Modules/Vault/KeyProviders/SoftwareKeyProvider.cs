using PatchManagement.Vault.Crypto;

namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The default <see cref="IKeyProvider"/> (ADR 0002): the KEK is held locally, loaded once at
/// startup from an <see cref="IKekSource"/>, and used to wrap/unwrap DEKs with AES-256-GCM. Zero
/// external dependency — works on-prem and air-gapped.
///
/// The keyset is loaded lazily and cached for the process lifetime behind a lock, because loading
/// touches the cold-start source (a file) and must happen exactly once. KEK material never leaves
/// this object except as ciphertext (wrapped DEKs).
/// </summary>
public sealed class SoftwareKeyProvider(IKekSource source) : IKeyProvider
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private KekKeyset? _keyset;

    public async Task<string> GetCurrentKeyIdAsync(CancellationToken ct)
    {
        var keyset = await EnsureLoadedAsync(ct);
        return keyset.CurrentKeyId;
    }

    public async Task<byte[]> WrapAsync(byte[] dek, string keyId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(dek);
        var keyset = await EnsureLoadedAsync(ct);
        return AesGcmEnvelope.Seal(keyset.Get(keyId), dek);
    }

    public async Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(wrappedDek);
        var keyset = await EnsureLoadedAsync(ct);
        var kek = keyset.Get(keyId);

        // Unwrap into a pinned, zeroed buffer, then hand back a right-sized copy. The frozen call
        // shape returns byte[]; the caller (DataKeyService/KekRotationService) pins and zeroes it.
        var length = AesGcmEnvelope.PlaintextLength(wrappedDek);
        using var plaintext = new PinnedBuffer(length);
        var written = AesGcmEnvelope.Open(kek, wrappedDek, plaintext.Span);
        return plaintext.Span[..written].ToArray();
    }

    public async Task<string> RotateMasterKeyAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            _keyset ??= await source.LoadAsync(ct);
            var newKeyId = _keyset.AddNewCurrent();
            await source.SaveAsync(_keyset, ct); // persist so the new version survives a restart
            return newKeyId;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<KekKeyset> EnsureLoadedAsync(CancellationToken ct)
    {
        if (_keyset is not null) return _keyset;
        await _gate.WaitAsync(ct);
        try
        {
            return _keyset ??= await source.LoadAsync(ct);
        }
        finally
        {
            _gate.Release();
        }
    }
}
