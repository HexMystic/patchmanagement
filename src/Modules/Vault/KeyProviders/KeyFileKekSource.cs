using System.Text.Json;
using System.Text.Json.Serialization;

namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The default software KEK cold-start source: a JSON key file holding the KEK versions, protected
/// by filesystem ACLs (THREAT-MODEL: "key file with strict permissions"). Supports unattended
/// restart because the KEK is at rest on the host — the documented, accepted tradeoff for on-prem.
///
/// On first boot the file does not exist; <see cref="LoadAsync"/> generates an initial keyset and
/// writes it. A rotation calls <see cref="SaveAsync"/> to persist the new version.
///
/// The file contains raw KEK material and is therefore NEVER logged. On POSIX hosts we tighten the
/// mode to 0600; on Windows the deployment is expected to rely on directory ACLs (documented, not
/// silently assumed).
/// </summary>
public sealed class KeyFileKekSource(string path) : IKekSource
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public async Task<KekKeyset> LoadAsync(CancellationToken ct)
    {
        if (!File.Exists(path))
        {
            var fresh = KekKeyset.CreateNew();
            await SaveAsync(fresh, ct);
            return fresh;
        }

        await using var stream = File.OpenRead(path);
        var doc = await JsonSerializer.DeserializeAsync<KeyFileDocument>(stream, JsonOptions, ct)
            ?? throw new InvalidOperationException($"KEK key file '{path}' is empty or malformed.");

        var keys = doc.Keys.ToDictionary(
            kv => kv.Key,
            kv => Convert.FromBase64String(kv.Value),
            StringComparer.Ordinal);
        return new KekKeyset(doc.Current, keys);
    }

    public async Task SaveAsync(KekKeyset keyset, CancellationToken ct)
    {
        var doc = new KeyFileDocument
        {
            Current = keyset.CurrentKeyId,
            Keys = keyset.Snapshot().ToDictionary(kv => kv.Key, kv => Convert.ToBase64String(kv.Value)),
        };

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        // Write to a temp file then atomically move, so a crash mid-write never truncates the
        // only copy of the KEK.
        var tempPath = path + ".tmp";
        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, doc, JsonOptions, ct);
        }
        HardenPermissions(tempPath);
        File.Move(tempPath, path, overwrite: true);
    }

    public string Describe() => $"keyfile:{path}";

    private static void HardenPermissions(string file)
    {
        if (OperatingSystem.IsWindows()) return; // deployment relies on directory ACLs (documented)
        try
        {
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (PlatformNotSupportedException)
        {
            // Best-effort: on hosts that cannot set the mode we still write the file; the
            // deployment guide requires a locked-down parent directory.
        }
    }

    private sealed class KeyFileDocument
    {
        [JsonPropertyName("current")] public string Current { get; set; } = string.Empty;
        [JsonPropertyName("keys")] public Dictionary<string, string> Keys { get; set; } = new();
    }
}
