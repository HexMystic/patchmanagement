using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The in-memory set of KEK versions held by the <see cref="SoftwareKeyProvider"/>: a map of
/// <c>keyId → 32-byte KEK</c> plus a pointer to the current version. Older versions are retained
/// so a DEK wrapped before a rotation still unwraps.
///
/// <para><b>Immutable.</b> Adding a version returns a NEW instance (<see cref="WithNewVersion"/>)
/// rather than mutating this one. That is what lets the provider publish a new keyset with a single
/// reference swap, only after it is durably stored — a reader mid-<see cref="Get"/> can never
/// observe a half-updated map, and a failed write cannot leave a version live in memory that is not
/// on disk (review C2/C4/H6, ADR 0015).</para>
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
        _keys = new Dictionary<string, byte[]>(keys, StringComparer.Ordinal);
        if (!_keys.ContainsKey(currentKeyId))
            throw new ArgumentException("currentKeyId must exist in keys.", nameof(currentKeyId));
        CurrentKeyId = currentKeyId;
    }

    public string CurrentKeyId { get; }

    /// <summary>A brand-new keyset with a single freshly generated 256-bit KEK.</summary>
    public static KekKeyset CreateNew()
    {
        var keyId = NewKeyId();
        var key = RandomNumberGenerator.GetBytes(32);
        return new KekKeyset(keyId, new Dictionary<string, byte[]> { [keyId] = key });
    }

    /// <summary>Looks up a version without throwing — used to decide whether a reload is warranted.</summary>
    public bool TryGet(string keyId, [MaybeNullWhen(false)] out byte[] key) => _keys.TryGetValue(keyId, out key);

    public byte[] Get(string keyId) =>
        TryGet(keyId, out var key)
            ? key
            : throw new KeyNotFoundException($"No KEK version '{keyId}' is loaded. Cannot unwrap.");

    /// <summary>
    /// A NEW keyset carrying every version of this one plus a freshly generated version, which
    /// becomes current. This instance is left unchanged — see the class remarks.
    /// </summary>
    public KekKeyset WithNewVersion()
    {
        var keyId = NewKeyId();
        var keys = new Dictionary<string, byte[]>(_keys, StringComparer.Ordinal)
        {
            [keyId] = RandomNumberGenerator.GetBytes(32),
        };
        return new KekKeyset(keyId, keys);
    }

    /// <summary>
    /// A copy for persistence by an <see cref="IKekSource"/> — a copy, not the live map, so a holder
    /// cannot observe or affect this keyset. Callers must not log it.
    /// </summary>
    public IReadOnlyDictionary<string, byte[]> Snapshot() =>
        new Dictionary<string, byte[]>(_keys, StringComparer.Ordinal);

    private static string NewKeyId() =>
        $"kek-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..40];

    public override string ToString() => $"KekKeyset(current={CurrentKeyId}, versions={_keys.Count}, keys=<redacted>)";
}
