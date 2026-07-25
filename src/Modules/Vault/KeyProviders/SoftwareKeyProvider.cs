using PatchManagement.Vault.Crypto;

namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The default <see cref="IKeyProvider"/> (ADR 0002): the KEK is held locally, loaded from an
/// <see cref="IKekSource"/>, and used to wrap/unwrap DEKs with AES-256-GCM. Zero external
/// dependency — works on-prem and air-gapped.
///
/// <para>The keyset is cached because loading touches the cold-start source, but the cache is NOT
/// authoritative (ADR 0015). It is replaced wholesale — a single reference swap of an immutable
/// value — and only ever AFTER the source has durably stored it, so a failed write cannot leave a
/// version live in memory that is absent from disk (review C4). On a lookup miss the keyset is
/// reloaded once before failing, so a version another process minted does not mean an outage until
/// restart (review C2).</para>
///
/// <para>KEK material never leaves this object except as ciphertext (wrapped DEKs).</para>
/// </summary>
public sealed class SoftwareKeyProvider(IKekSource source) : IKeyProvider
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    // volatile: the fast path in EnsureLoadedAsync reads this without taking the gate.
    private volatile KekKeyset? _keyset;

    public async Task<string> GetCurrentKeyIdAsync(CancellationToken ct)
    {
        var keyset = await EnsureLoadedAsync(ct);
        return keyset.CurrentKeyId;
    }

    public async Task<byte[]> WrapAsync(byte[] dek, string keyId, KeyBinding binding, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(dek);
        var kek = await ResolveKeyAsync(keyId, ct);
        return AesGcmEnvelope.Seal(kek, dek, AssociatedData(binding));
    }

    public async Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, KeyBinding binding, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(wrappedDek);
        var kek = await ResolveKeyAsync(keyId, ct);

        // Unwrap into a pinned, zeroed buffer, then hand back a right-sized copy. The frozen call
        // shape returns byte[]; the caller (DataKeyService/KekRotationService) pins and zeroes it.
        var length = AesGcmEnvelope.PlaintextLength(wrappedDek);
        using var plaintext = new PinnedBuffer(length);
        var written = AesGcmEnvelope.Open(kek, wrappedDek, plaintext.Span, AssociatedData(binding));
        return plaintext.Span[..written].ToArray();
    }

    public async Task<string> RotateMasterKeyAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            // The source performs the whole read-modify-write atomically and does not return until
            // the new version is durable. Only then does it become the keyset this process uses —
            // if the write throws, the cache is untouched and nothing was minted as far as we care.
            var updated = await source.AddVersionAsync(ct);
            _keyset = updated;
            return updated.CurrentKeyId;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Resolves a KEK version, reloading once if it is unknown. Another process may have added the
    /// version since this one last loaded; without the reload that would be a hard failure until
    /// restart.
    /// </summary>
    private async Task<byte[]> ResolveKeyAsync(string keyId, CancellationToken ct)
    {
        var keyset = await EnsureLoadedAsync(ct);
        if (keyset.TryGet(keyId, out var key)) return key;

        var reloaded = await ReloadAsync(ct);
        return reloaded.Get(keyId); // still unknown => genuinely absent, and Get says so loudly
    }

    private async Task<KekKeyset> ReloadAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var fresh = await source.LoadAsync(ct);
            _keyset = fresh;
            return fresh;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<KekKeyset> EnsureLoadedAsync(CancellationToken ct)
    {
        var cached = _keyset;
        if (cached is not null) return cached;

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

    /// <summary>This provider binds by AES-GCM associated data; other backends map the same
    /// <see cref="KeyBinding"/> onto their own mechanism (ADR 0013).</summary>
    private static byte[] AssociatedData(KeyBinding binding) =>
        EnvelopeBinding.ForDataKey(binding.TenantId, binding.DataKeyId);
}
