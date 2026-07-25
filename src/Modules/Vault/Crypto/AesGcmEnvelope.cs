using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PatchManagement.Vault.Crypto;

/// <summary>
/// AES-256-GCM authenticated encryption, used for BOTH layers of the envelope:
/// the KEK wrapping a DEK, and a DEK sealing a credential payload.
///
/// Wire format:
/// <code>
/// [ version:1 ][ nonce:12 ][ tag:16 ][ ciphertext:n ]
/// </code>
/// A random 96-bit nonce is generated per call — never reused for a given key — which is the
/// standard safe construction for GCM. The tag authenticates the ciphertext, so tampering or an
/// unwrap with the wrong key fails loudly (<see cref="CryptographicException"/>) rather than
/// returning garbage.
///
/// <para><b>The blob is NOT self-describing: decryption also requires the caller's associated
/// data.</b> Every <see cref="Seal"/>/<see cref="Open"/> pair must supply the identical binding —
/// see <see cref="EnvelopeBinding"/> — which ties the ciphertext to the row that stores it. Opening
/// with a different binding fails authentication, so an envelope copied into another tenant's row
/// cannot be decrypted. This is what version <c>0x02</c> denotes; the unbound <c>0x01</c> format is
/// rejected outright rather than accepted, so there is no downgrade path (ADR 0013).</para>
/// </summary>
internal static class AesGcmEnvelope
{
    private const byte Version = 0x02;
    private const int NonceSize = 12; // AesGcm.NonceByteSizes standard
    private const int TagSize = 16;   // AesGcm.TagByteSizes max
    private const int KeySize = 32;   // AES-256
    private const int HeaderSize = 1 + NonceSize + TagSize;

    public static int KeySizeBytes => KeySize;

    /// <summary>
    /// Encrypt <paramref name="plaintext"/> under <paramref name="key"/> (32 bytes) into a fresh
    /// envelope blob, bound to <paramref name="associatedData"/>. Does not retain or log any input.
    /// </summary>
    /// <param name="associatedData">
    /// Authenticated but not encrypted. <see cref="Open"/> must be given the identical value or it
    /// fails authentication — this is what binds the ciphertext to its row. Build it with
    /// <see cref="EnvelopeBinding"/>.
    /// </param>
    public static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        RequireKey(key);

        var result = new byte[HeaderSize + plaintext.Length];
        result[0] = Version;
        var nonce = result.AsSpan(1, NonceSize);
        var tag = result.AsSpan(1 + NonceSize, TagSize);
        var ciphertext = result.AsSpan(HeaderSize);

        RandomNumberGenerator.Fill(nonce);
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return result;
    }

    /// <summary>
    /// Decrypt an envelope produced by <see cref="Seal"/> into <paramref name="destination"/>,
    /// which must be at least <see cref="PlaintextLength"/> bytes. Returns the number of bytes
    /// written.
    /// </summary>
    /// <param name="associatedData">
    /// Must be byte-identical to the value passed to <see cref="Seal"/>. A mismatch — the signature
    /// of an envelope moved to a different row or tenant — raises
    /// <see cref="AuthenticationTagMismatchException"/>.
    /// </param>
    /// <exception cref="AuthenticationTagMismatchException">
    /// Authentication failed: wrong key, tampered ciphertext, or a binding that does not match the
    /// one used to seal.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The blob is structurally invalid — too short, or an unsupported version such as the unbound
    /// <c>0x01</c> format. Distinct from an authentication failure, deliberately: an operator
    /// reading the error should be able to tell a format problem from a binding violation.
    /// </exception>
    public static int Open(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> envelope, Span<byte> destination, ReadOnlySpan<byte> associatedData)
    {
        RequireKey(key);
        if (envelope.Length < HeaderSize)
            throw new CryptographicException("Envelope is too short to be valid.");
        if (envelope[0] != Version)
            throw new CryptographicException($"Unsupported envelope version {envelope[0]}.");

        var nonce = envelope.Slice(1, NonceSize);
        var tag = envelope.Slice(1 + NonceSize, TagSize);
        var ciphertext = envelope[HeaderSize..];
        if (destination.Length < ciphertext.Length)
            throw new ArgumentException("Destination is too small for the plaintext.", nameof(destination));

        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, destination[..ciphertext.Length], associatedData);
        return ciphertext.Length;
    }

    /// <summary>The plaintext length that <see cref="Open"/> will produce for this envelope.</summary>
    public static int PlaintextLength(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < HeaderSize)
            throw new CryptographicException("Envelope is too short to be valid.");
        return envelope.Length - HeaderSize;
    }

    private static void RequireKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes (AES-256).", nameof(key));
    }

    /// <summary>Helper used by tests/wire encoders needing the LE length prefix convention.</summary>
    internal static void WriteInt32(Span<byte> destination, int value) =>
        BinaryPrimitives.WriteInt32LittleEndian(destination, value);

    internal static int ReadInt32(ReadOnlySpan<byte> source) =>
        BinaryPrimitives.ReadInt32LittleEndian(source);
}
