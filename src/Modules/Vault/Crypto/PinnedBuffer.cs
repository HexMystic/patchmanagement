using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PatchManagement.Vault.Crypto;

/// <summary>
/// A fixed-size byte buffer pinned in memory for the lifetime of the object and
/// cryptographically zeroed on <see cref="Dispose"/>.
///
/// Pinning (<see cref="GCHandleType.Pinned"/>) stops the GC from relocating the buffer during
/// compaction, which would otherwise leave stale copies of plaintext scattered across the heap.
/// Per THREAT-MODEL, every transient secret — the unwrapped DEK and the decrypted credential
/// payload — lives in one of these and is zeroed the instant it is no longer needed.
///
/// LIMITATION (review M7): the final hop into <c>ResolvedCredential</c> is an ordinary managed
/// <c>byte[]</c> because that frozen contract owns an unpinned array. We do not change the frozen
/// type; we minimise the unpinned window by pinning everything up to that last copy.
/// </summary>
internal sealed class PinnedBuffer : IDisposable
{
    private readonly byte[] _bytes;
    private GCHandle _handle;
    private bool _disposed;

    public PinnedBuffer(int size)
    {
        _bytes = new byte[size];
        _handle = GCHandle.Alloc(_bytes, GCHandleType.Pinned);
    }

    public byte[] Bytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _bytes;
        }
    }

    public Span<byte> Span => Bytes;

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_bytes);
        if (_handle.IsAllocated) _handle.Free();
        _disposed = true;
    }
}
