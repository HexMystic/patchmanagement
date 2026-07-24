using System.Security.Cryptography;

namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The in-memory set of KEK versions held by the <see cref="SoftwareKeyProvider"/>: a map of
/// <c>keyId → 32-byte KEK</c> plus a pointer to the current version. Older versions are retained
/// so a DEK wrapped before a rotation still unwraps.
///
/// This holds raw KEK material, so it is never logged or serialized except by an
/// <see cref="IKekSource"/> persisting it to its cold-start store (e.g. a permission-locked key
/// file). <see cref="ToString"/> is redacted.
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

    public string CurrentKeyId { get; private set; }

    public IReadOnlyCollection<string> KeyIds => _keys.Keys;

    /// <summary>A brand-new keyset with a single freshly generated 256-bit KEK.</summary>
    public static KekKeyset CreateNew()
    {
        var keyId = NewKeyId();
        var key = RandomNumberGenerator.GetBytes(32);
        return new KekKeyset(keyId, new Dictionary<string, byte[]> { [keyId] = key });
    }

    public byte[] Get(string keyId) =>
        _keys.TryGetValue(keyId, out var key)
            ? key
            : throw new KeyNotFoundException($"No KEK version '{keyId}' is loaded. Cannot unwrap.");

    /// <summary>Add a freshly generated KEK version, make it current, and return its keyId.</summary>
    public string AddNewCurrent()
    {
        var keyId = NewKeyId();
        _keys[keyId] = RandomNumberGenerator.GetBytes(32);
        CurrentKeyId = keyId;
        return keyId;
    }

    /// <summary>Snapshot for persistence by an <see cref="IKekSource"/>. Callers must not log this.</summary>
    public IReadOnlyDictionary<string, byte[]> Snapshot() => _keys;

    private static string NewKeyId() =>
        $"kek-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..40];

    public override string ToString() => $"KekKeyset(current={CurrentKeyId}, versions={_keys.Count}, keys=<redacted>)";
}
