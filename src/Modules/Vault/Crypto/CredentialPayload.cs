using System.Text;

namespace PatchManagement.Vault.Crypto;

/// <summary>
/// The plaintext that goes INSIDE the DEK-sealed envelope. The frozen <c>credentials</c> table
/// (Phase 1) has no username column, and the login name must survive a round-trip so the Phase 3
/// connector can authenticate. We therefore pack the (non-secret) username together with the
/// secret material into the encrypted envelope — the username rides inside the ciphertext rather
/// than sitting in a plaintext column, which is strictly safer, not weaker.
///
/// Wire format:
/// <code>
/// [ usernameLen:4 LE ][ username:utf8 ][ secret:n ]
/// </code>
/// usernameLen == -1 encodes a null username (distinct from an empty one).
/// </summary>
internal static class CredentialPayload
{
    /// <summary>
    /// Serialize into <paramref name="destination"/>; returns bytes written. The caller owns a
    /// pinned buffer sized by <see cref="Size"/> and zeroes it afterwards.
    /// </summary>
    public static int Write(Span<byte> destination, string? username, ReadOnlySpan<byte> secret)
    {
        var usernameBytes = username is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(username);
        var len = username is null ? -1 : usernameBytes.Length;

        AesGcmEnvelope.WriteInt32(destination, len);
        var offset = 4;
        if (len > 0)
        {
            usernameBytes.CopyTo(destination[offset..]);
            offset += usernameBytes.Length;
        }
        secret.CopyTo(destination[offset..]);
        offset += secret.Length;

        // Do not leave the username copy lying around unpinned.
        Array.Clear(usernameBytes);
        return offset;
    }

    public static int Size(string? username, int secretLength)
    {
        var usernameLen = username is null ? 0 : Encoding.UTF8.GetByteCount(username);
        return 4 + usernameLen + secretLength;
    }

    /// <summary>
    /// Parse a payload previously written by <see cref="Write"/>. The username is returned as a
    /// managed string (it is not a secret); the secret bytes remain a slice of the caller's pinned
    /// buffer and are copied out by the caller into their final destination.
    /// </summary>
    public static ReadOnlySpan<byte> Read(ReadOnlySpan<byte> payload, out string? username)
    {
        var len = AesGcmEnvelope.ReadInt32(payload);
        if (len == -1)
        {
            username = null;
            return payload[4..];
        }

        username = Encoding.UTF8.GetString(payload.Slice(4, len));
        return payload[(4 + len)..];
    }
}
