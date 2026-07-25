using System.Security.Cryptography;
using System.Text;
using PatchManagement.Vault.Crypto;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>Unit coverage for the AES-GCM envelope and the credential payload codec.</summary>
public sealed class CryptoTests
{
    /// <summary>A distinct row binding per call — the associated data under test (ADR 0013).</summary>
    private static byte[] Binding() =>
        EnvelopeBinding.ForCredential(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());

    [Fact]
    public void Envelope_round_trips_plaintext()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("super-secret-password");
        var aad = Binding();

        var envelope = AesGcmEnvelope.Seal(key, plaintext, aad);
        var buffer = new byte[AesGcmEnvelope.PlaintextLength(envelope)];
        var written = AesGcmEnvelope.Open(key, envelope, buffer, aad);

        Assert.Equal(plaintext, buffer[..written]);
    }

    [Fact]
    public void Envelope_uses_a_fresh_nonce_so_ciphertext_differs_each_time()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("same input");
        var aad = Binding();

        var a = AesGcmEnvelope.Seal(key, plaintext, aad);
        var b = AesGcmEnvelope.Seal(key, plaintext, aad);

        Assert.NotEqual(a, b); // different nonce => different bytes
    }

    [Fact]
    public void Open_with_the_wrong_key_fails_authentication()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var wrong = RandomNumberGenerator.GetBytes(32);
        var aad = Binding();
        var envelope = AesGcmEnvelope.Seal(key, Encoding.UTF8.GetBytes("x"), aad);

        var buffer = new byte[AesGcmEnvelope.PlaintextLength(envelope)];
        Assert.ThrowsAny<AuthenticationTagMismatchException>(
            () => AesGcmEnvelope.Open(wrong, envelope, buffer, aad));
    }

    [Fact]
    public void Open_of_tampered_ciphertext_fails_authentication()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var aad = Binding();
        var envelope = AesGcmEnvelope.Seal(key, Encoding.UTF8.GetBytes("integrity matters"), aad);
        envelope[^1] ^= 0xFF; // flip a ciphertext bit

        var buffer = new byte[AesGcmEnvelope.PlaintextLength(envelope)];
        Assert.ThrowsAny<AuthenticationTagMismatchException>(
            () => AesGcmEnvelope.Open(key, envelope, buffer, aad));
    }

    /// <summary>
    /// The unit-level statement of ADR 0013: the same key and the same untampered ciphertext still
    /// fail when the binding differs. Asserts the tag-mismatch subclass specifically — a bare
    /// CryptographicException would also be raised by the structural checks, so the looser assertion
    /// could pass without the associated data ever being consulted.
    /// </summary>
    [Fact]
    public void Open_with_a_different_binding_fails_authentication()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var envelope = AesGcmEnvelope.Seal(key, Encoding.UTF8.GetBytes("bound to one row"), Binding());

        var buffer = new byte[AesGcmEnvelope.PlaintextLength(envelope)];
        Assert.ThrowsAny<AuthenticationTagMismatchException>(
            () => AesGcmEnvelope.Open(key, envelope, buffer, Binding()));
    }

    /// <summary>
    /// The unbound 0x01 format is refused as a downgrade, and refused DIAGNOSTICALLY: an operator
    /// must be able to tell "wrong format" from "binding violation". Proves the version check fires
    /// first, rather than the blob failing incidentally on the tag.
    /// </summary>
    [Fact]
    public void Open_of_a_version_1_envelope_is_rejected_as_an_unsupported_version()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var aad = Binding();
        var envelope = AesGcmEnvelope.Seal(key, Encoding.UTF8.GetBytes("legacy"), aad);
        envelope[0] = 0x01; // downgrade the version byte to the old unbound format

        var buffer = new byte[AesGcmEnvelope.PlaintextLength(envelope)];
        var ex = Assert.ThrowsAny<CryptographicException>(
            () => AesGcmEnvelope.Open(key, envelope, buffer, aad));

        Assert.Contains("Unsupported envelope version", ex.Message, StringComparison.Ordinal);
        Assert.IsNotType<AuthenticationTagMismatchException>(ex); // refused by the version check, not the tag
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
