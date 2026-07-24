using System.Security.Cryptography;
using System.Text;
using PatchManagement.Vault.Crypto;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>Unit coverage for the AES-GCM envelope and the credential payload codec.</summary>
public sealed class CryptoTests
{
    [Fact]
    public void Envelope_round_trips_plaintext()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("super-secret-password");

        var envelope = AesGcmEnvelope.Seal(key, plaintext);
        var buffer = new byte[AesGcmEnvelope.PlaintextLength(envelope)];
        var written = AesGcmEnvelope.Open(key, envelope, buffer);

        Assert.Equal(plaintext, buffer[..written]);
    }

    [Fact]
    public void Envelope_uses_a_fresh_nonce_so_ciphertext_differs_each_time()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("same input");

        var a = AesGcmEnvelope.Seal(key, plaintext);
        var b = AesGcmEnvelope.Seal(key, plaintext);

        Assert.NotEqual(a, b); // different nonce => different bytes
    }

    [Fact]
    public void Open_with_the_wrong_key_fails_authentication()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var wrong = RandomNumberGenerator.GetBytes(32);
        var envelope = AesGcmEnvelope.Seal(key, Encoding.UTF8.GetBytes("x"));

        var buffer = new byte[AesGcmEnvelope.PlaintextLength(envelope)];
        Assert.ThrowsAny<CryptographicException>(() => AesGcmEnvelope.Open(wrong, envelope, buffer));
    }

    [Fact]
    public void Open_of_tampered_ciphertext_fails_authentication()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var envelope = AesGcmEnvelope.Seal(key, Encoding.UTF8.GetBytes("integrity matters"));
        envelope[^1] ^= 0xFF; // flip a ciphertext bit

        var buffer = new byte[AesGcmEnvelope.PlaintextLength(envelope)];
        Assert.ThrowsAny<CryptographicException>(() => AesGcmEnvelope.Open(key, envelope, buffer));
    }

    [Fact]
    public void Payload_round_trips_username_and_secret()
    {
        var secret = Encoding.UTF8.GetBytes("p@ss");
        var size = CredentialPayload.Size("administrator", secret.Length);
        var buffer = new byte[size];

        var written = CredentialPayload.Write(buffer, "administrator", secret);
        var readSecret = CredentialPayload.Read(buffer.AsSpan(0, written), out var username);

        Assert.Equal("administrator", username);
        Assert.Equal(secret, readSecret.ToArray());
    }

    [Fact]
    public void Payload_distinguishes_null_username_from_empty()
    {
        var secret = Encoding.UTF8.GetBytes("k");

        var nullBuf = new byte[CredentialPayload.Size(null, secret.Length)];
        var nullLen = CredentialPayload.Write(nullBuf, null, secret);
        CredentialPayload.Read(nullBuf.AsSpan(0, nullLen), out var nullName);
        Assert.Null(nullName);

        var emptyBuf = new byte[CredentialPayload.Size("", secret.Length)];
        var emptyLen = CredentialPayload.Write(emptyBuf, "", secret);
        CredentialPayload.Read(emptyBuf.AsSpan(0, emptyLen), out var emptyName);
        Assert.Equal("", emptyName);
    }

    [Fact]
    public void Pinned_buffer_zeroes_on_dispose()
    {
        var buffer = new PinnedBuffer(16);
        buffer.Span.Fill(0xAB);
        var bytes = buffer.Bytes;
        buffer.Dispose();
        Assert.All(bytes, b => Assert.Equal(0, b));
    }
}
