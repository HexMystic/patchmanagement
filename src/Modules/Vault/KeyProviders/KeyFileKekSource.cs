using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The default software KEK cold-start source: a JSON key file holding the KEK versions, protected
/// by filesystem ACLs (THREAT-MODEL: "key file with strict permissions"). Supports unattended
/// restart because the KEK is at rest on the host — the documented, accepted tradeoff for on-prem.
///
/// <para>The write path is the whole point of this type, because losing a KEK version bricks every
/// DEK under it. Adding a version (ADR 0015):</para>
/// <list type="number">
///   <item>take an exclusive lock on a sidecar file — held across the entire read-modify-write, and
///   enforced by the OS, so a second PROCESS cannot interleave;</item>
///   <item>re-read the keyset FROM DISK — never from a cache. This is what makes concurrent
///   rotations additive: the second writer sees the first one's version and keeps it, instead of
///   overwriting the file with its own stale snapshot (review C2);</item>
///   <item>write a temp file, flush it to the physical disk, atomically rename it over the key file,
///   then fsync the directory so the rename itself survives a power loss (review C3);</item>
///   <item>only then return, so the caller can never wrap data under a version that is not durably
///   stored (review C4).</item>
/// </list>
///
/// <para>The file contains raw KEK material and is therefore NEVER logged. It is created 0600 on
/// POSIX hosts at creation time rather than hardened afterwards, so there is no window in which it
/// is readable by others (review H2); on Windows the deployment relies on directory ACLs
/// (documented, not silently assumed).</para>
/// </summary>
/// <param name="path">Where the key file lives.</param>
/// <param name="allowInitialize">
/// Whether an ABSENT store may be initialized with a fresh KEK. Default false, and it must stay
/// false in any deployment that already holds credentials: absence is far more often a lost mount
/// or a wrong path than a genuine first boot, and minting a key in that moment strands every
/// existing DEK (re-review CR-1). It only ever applies to <see cref="LoadOrInitializeAsync"/>.
/// </param>
public sealed class KeyFileKekSource(string path, bool allowInitialize = false) : IKekSource
{
    private const string TempSuffix = ".tmp";
    private const string LockSuffix = ".lock";

    /// <summary>How long to wait for another process to finish its read-modify-write.</summary>
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public async Task<KekKeyset> LoadOrInitializeAsync(CancellationToken ct)
    {
        using var _ = await AcquireLockAsync(ct);

        if (File.Exists(path)) return await ReadFileAsync(ct);
        if (!allowInitialize) throw NotInitialized();

        var fresh = KekKeyset.CreateNew();
        await WriteDurablyAsync(fresh, ct);
        return fresh;
    }

    public async Task<KekKeyset> ReadAsync(CancellationToken ct)
    {
        using var _ = await AcquireLockAsync(ct);
        return await ReadRequiredAsync(ct);
    }

    public async Task<KekKeyset> AddVersionAsync(CancellationToken ct)
    {
        using var _ = await AcquireLockAsync(ct);

        // Read-modify-write under the lock. The keyset we extend is the one on DISK, so a version
        // another process added since we last loaded is carried forward rather than erased — and if
        // the store has vanished we fail rather than mint a replacement, which would discard every
        // version we were meant to carry forward (CR-1).
        var onDisk = await ReadRequiredAsync(ct);
        var updated = onDisk.WithNewVersion();
        await WriteDurablyAsync(updated, ct);
        return updated;
    }

    public string Describe() => $"keyfile:{path}";

    /// <summary>Read the store, treating absence as the error it almost always is. Lock must be held.</summary>
    private async Task<KekKeyset> ReadRequiredAsync(CancellationToken ct)
    {
        if (!File.Exists(path)) throw NotInitialized();
        return await ReadFileAsync(ct);
    }

    /// <summary>
    /// Deliberately actionable: absence is either a genuine first boot or — far more likely once a
    /// system is running — a lost mount or a wrong path, and the two are indistinguishable from here.
    /// </summary>
    private InvalidOperationException NotInitialized() => new(
        $"The KEK store '{Path.GetFullPath(path)}' does not exist, so no key material can be read. " +
        "If this is a genuine first boot, set VAULT_SOFTWARE_KEK_INIT=true once to initialize it. " +
        "If credentials already exist, DO NOT initialize: the store is missing or unreachable (an " +
        "unmounted volume, a wrong path, a changed working directory), and minting a new KEK would " +
        "leave every existing credential permanently unrecoverable. Restore the key file instead.");

    private async Task<KekKeyset> ReadFileAsync(CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        var doc = await JsonSerializer.DeserializeAsync<KeyFileDocument>(stream, JsonOptions, ct)
            ?? throw new InvalidOperationException($"KEK key file '{path}' is empty or malformed.");

        var keys = doc.Keys.ToDictionary(
            kv => kv.Key,
            kv => Convert.FromBase64String(kv.Value),
            StringComparer.Ordinal);
        return new KekKeyset(doc.Current, keys);
    }

    /// <summary>
    /// Persist the keyset so that, after any crash, the file on disk is either the previous keyset or
    /// this one — never a torn or zero-length file, and never missing a version it once held.
    /// </summary>
    private async Task WriteDurablyAsync(KekKeyset keyset, CancellationToken ct)
    {
        // Snapshot hands back fresh arrays this method owns (re-review H-1), so they are zeroed the
        // moment they have been encoded rather than left to the GC. The base64 strings that replace
        // them are immutable and cannot be zeroed — the recorded KEK memory-hygiene limitation,
        // unchanged here; this only stops a second, avoidable copy of the raw material persisting.
        var snapshot = keyset.Snapshot();
        KeyFileDocument doc;
        try
        {
            doc = new KeyFileDocument
            {
                Current = keyset.CurrentKeyId,
                Keys = snapshot.ToDictionary(kv => kv.Key, kv => Convert.ToBase64String(kv.Value)),
            };
        }
        finally
        {
            foreach (var key in snapshot.Values) CryptographicOperations.ZeroMemory(key);
        }

        EnsureDirectory();
        var tempPath = path + TempSuffix;

        try
        {
            await using (var stream = new FileStream(
                tempPath, CreateOptions(FileMode.Create, FileAccess.Write, FileOptions.WriteThrough)))
            {
                await JsonSerializer.SerializeAsync(stream, doc, JsonOptions, ct);
                await stream.FlushAsync(ct);

                // WriteThrough alone is not a guarantee on every filesystem; ask explicitly for the
                // bytes to reach the device before the rename makes them the only copy.
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, path, overwrite: true);
            FsyncDirectory();
        }
        catch
        {
            // Never leave a partial key file behind — it holds real key material.
            TryDelete(tempPath);
            throw;
        }
    }

    private void EnsureDirectory()
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
    }

    /// <summary>
    /// Exclusive across processes: <see cref="FileShare.None"/> is enforced by the OS per handle —
    /// mandatory on Windows, an advisory <c>flock</c> on Unix — so a second process opening the same
    /// sidecar blocks until this one releases it.
    ///
    /// <para>A sidecar rather than the key file itself, because the atomic rename replaces the key
    /// file, which would invalidate a lock held on it mid-write.</para>
    /// </summary>
    private async Task<IDisposable> AcquireLockAsync(CancellationToken ct)
    {
        EnsureDirectory();
        var lockPath = path + LockSuffix;
        var deadline = DateTime.UtcNow + LockTimeout;
        var delay = TimeSpan.FromMilliseconds(10);

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    lockPath, CreateOptions(FileMode.OpenOrCreate, FileAccess.ReadWrite, FileOptions.None));
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                await Task.Delay(delay, ct);
                delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 250));
            }
            catch (IOException ex)
            {
                throw new TimeoutException(
                    $"Timed out after {LockTimeout.TotalSeconds:N0}s waiting for the KEK key-file lock " +
                    $"'{lockPath}'. Another process may be rotating, or a stale lock is held.", ex);
            }
        }
    }

    /// <summary>
    /// Options that create the file 0600 on POSIX at creation time — no window where the key
    /// material is world-readable. <c>UnixCreateMode</c> is not settable on Windows, which relies on
    /// directory ACLs (the same split as the rest of this type).
    /// </summary>
    private static FileStreamOptions CreateOptions(FileMode mode, FileAccess access, FileOptions options)
    {
        var streamOptions = new FileStreamOptions
        {
            Mode = mode,
            Access = access,
            Share = FileShare.None,
            Options = options,
        };

        if (!OperatingSystem.IsWindows())
            streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        return streamOptions;
    }

    /// <summary>
    /// Makes the RENAME durable. Flushing the temp file only guarantees its CONTENTS survive; on
    /// Unix the directory entry that points at it is separate metadata, so without this a power loss
    /// can silently revert to the previous key file — losing a version we already reported as
    /// current. .NET exposes no managed API for it, hence the P/Invoke.
    ///
    /// <para>Best-effort: a failure here is not fatal (the previous keyset is still intact and the
    /// new one is written), so it does not fail the rotation. On Windows this is a no-op — NTFS
    /// journals the rename and there is no directory handle to sync.</para>
    /// </summary>
    private void FsyncDirectory()
    {
        if (OperatingSystem.IsWindows()) return;

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (string.IsNullOrEmpty(directory)) return;

        const int ORdonly = 0;
        var fd = Open(Encoding.UTF8.GetBytes(directory + '\0'), ORdonly);
        if (fd < 0) return;

        try { Fsync(fd); }
        finally { Close(fd); }
    }

    private static void TryDelete(string file)
    {
        try { File.Delete(file); }
        catch (IOException) { /* best-effort cleanup; the throw below carries the real failure */ }
        catch (UnauthorizedAccessException) { /* ditto */ }
    }

    // DllImport rather than the source-generated LibraryImport: the latter requires
    // AllowUnsafeBlocks, and enabling unsafe code across a module that handles key material is a
    // poor trade for three calls with no pointer arguments. The path is marshalled as an explicit
    // null-terminated UTF-8 byte array so there is no CharSet ambiguity.
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(byte[] pathname, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int fd);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int fd);

    private sealed class KeyFileDocument
    {
        [JsonPropertyName("current")] public string Current { get; set; } = string.Empty;
        [JsonPropertyName("keys")] public Dictionary<string, string> Keys { get; set; } = new();
    }
}
