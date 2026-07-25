using System.Security.Cryptography;

namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The in-memory set of KEK versions held by the <see cref="SoftwareKeyProvider"/>: a map of
/// <c>keyId → 32-byte KEK</c> plus a pointer to the current version. Older versions are retained
/// so a DEK wrapped before a rotation still unwraps.
///
/// <para><b>Immutable — including the key material.</b> Adding a version returns a NEW instance
/// (<see cref="WithNewVersion"/>) rather than mutating this one. That is what lets the provider
/// publish a new keyset with a single reference swap, only after it is durably stored — a reader
/// mid-lookup can never observe a half-updated map, and a failed write cannot leave a version live
/// in memory that is not on disk (review C2/C4/H6, ADR 0015).</para>
///
/// <para>Immutability is genuine rather than structural: this type <b>owns</b> its key material.
/// Every array is deep-copied on the way in (the constructor, <see cref="WithNewVersion"/>) and on
/// the way out (<see cref="CopyKeyTo"/>, <see cref="Snapshot"/>), so no caller holds a reference
/// that could mutate or zero a live KEK. An earlier version copied only the dictionary, which left
/// every version aliased by whoever last touched it — including across a
/// <see cref="WithNewVersion"/> boundary, so a parent and its child shared arrays (re-review H-1).
/// </para>
///
/// <para>This holds raw KEK material, so it is never logged or serialized except by an
/// <see cref="IKekSource"/> persisting it to its cold-start store. <see cref="ToString"/> is
/// redacted.</para>
/// </summary>
public sealed class KekKeyset
{
    private readonly Dictionary<string, byte[]> _keys;

    public KekKeyset(string currentKeyId, IReadOnlyDictionary<string, byte[]> keys)
    {
        if (string.IsNullOrWhiteSpace(currentKeyId))
            throw new ArgumentException("currentKeyId is required.", nameof(currentKeyId));
        ArgumentNullException.ThrowIfNull(keys);

        _keys = new Dictionary<string, byte[]>(keys.Count, StringComparer.Ordinal);
        foreach (var (keyId, key) in keys)
        {
            if (key is null)
                throw new ArgumentException($"KEK version '{keyId}' has no key material.", nameof(keys));

            // Deep copy: the caller keeps its arrays, we keep ours. Without this the caller could
            // mutate or zero a live KEK after handing it over.
            _keys[keyId] = key.AsSpan().ToArray();
        }

        if (!_keys.ContainsKey(currentKeyId))
            throw new ArgumentException("currentKeyId must exist in keys.", nameof(keys));
        CurrentKeyId = currentKeyId;
    }

    public string CurrentKeyId { get; }

    /// <summary>A brand-new keyset with a single freshly generated 256-bit KEK.</summary>
    public static KekKeyset CreateNew()
    {
        var keyId = NewKeyId();
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            return new KekKeyset(keyId, new Dictionary<string, byte[]> { [keyId] = key });
        }
        finally
        {
            // The constructor took its own copy, so this transient one must not outlive the call.
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Whether a version is loaded. A pure predicate — it hands out no key material — so the
    /// provider can decide whether a reload is warranted without materialising a KEK first.
    /// </summary>
    public bool Contains(string keyId) => _keys.ContainsKey(keyId);

    /// <summary>
    /// Copies a KEK version into a caller-owned buffer, which is the ONLY way key material leaves
    /// this type. The caller supplies the destination — in practice a
    /// <see cref="Crypto.PinnedBuffer"/> — so the material goes straight from this keyset into a
    /// pinned, self-zeroing buffer with no intermediate array to leak or forget.
    /// </summary>
    /// <exception cref="KeyNotFoundException">The version is not loaded.</exception>
    /// <exception cref="ArgumentException">
    /// The destination is not exactly the size of the stored version. Loud on purpose: a
    /// wrong-sized KEK means a malformed key store, and silently truncating one would produce
    /// ciphertext nothing can open.
    /// </exception>
    public void CopyKeyTo(string keyId, Span<byte> destination)
    {
        if (!_keys.TryGetValue(keyId, out var key))
            throw new KeyNotFoundException($"No KEK version '{keyId}' is loaded. Cannot unwrap.");

        if (destination.Length != key.Length)
            throw new ArgumentException(
                $"Destination is {destination.Length} bytes but KEK version '{keyId}' is {key.Length}.",
                nameof(destination));

        key.CopyTo(destination);
    }

    /// <summary>
    /// A NEW keyset carrying every version of this one plus a freshly generated version, which
    /// becomes current. This instance is left unchanged, and the two share no arrays — see the
    /// class remarks.
    /// </summary>
    public KekKeyset WithNewVersion()
    {
        var keyId = NewKeyId();
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            // The constructor deep-copies, so the new keyset aliases neither this one nor `key`.
            var keys = new Dictionary<string, byte[]>(_keys, StringComparer.Ordinal)
            {
                [keyId] = key,
            };
            return new KekKeyset(keyId, keys);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Deep copies for persistence by an <see cref="IKekSource"/> — fresh arrays, not the live
    /// ones, so a holder can neither observe nor affect this keyset. The caller owns what it gets
    /// back and should zero it once written. Callers must not log it.
    /// </summary>
    public IReadOnlyDictionary<string, byte[]> Snapshot()
    {
        var copy = new Dictionary<string, byte[]>(_keys.Count, StringComparer.Ordinal);
        foreach (var (keyId, key) in _keys) copy[keyId] = key.AsSpan().ToArray();
        return copy;
    }

    private static string NewKeyId() =>
        $"kek-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..40];

    public override string ToString() => $"KekKeyset(current={CurrentKeyId}, versions={_keys.Count}, keys=<redacted>)";
}
