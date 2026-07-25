using PatchManagement.Vault.Crypto;
using PatchManagement.Vault.KeyProviders;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Pins the ownership half of <see cref="KekKeyset"/>'s immutability (re-review H-1). ADR 0015 made
/// the keyset structurally immutable — a new instance per version, published by reference swap — but
/// every accessor still handed out the live <c>byte[]</c>, so a caller could mutate or zero a KEK
/// that the provider was concurrently wrapping under. Structural immutability over shared mutable
/// arrays is not immutability, and these assert the difference.
///
/// <para>Each test mutates what it was given and then re-reads through the keyset: if the keyset
/// still returns the original byte, it owns its material; if it returns the mutation, it does not.
/// </para>
/// </summary>
public sealed class KekKeysetTests
{
    private const int KekSize = 32;

    [Fact]
    public void A_copied_key_is_the_callers_alone_to_mutate()
    {
        var keyset = KekKeyset.CreateNew();

        var first = Read(keyset, keyset.CurrentKeyId);
        first[0] ^= 0xFF;

        var second = Read(keyset, keyset.CurrentKeyId);
        Assert.NotEqual(first[0], second[0]);
    }

    [Fact]
    public void Zeroing_a_copied_key_does_not_destroy_the_live_keyset()
    {
        // The failure this rules out is worse than mutation: PinnedBuffer.Dispose zeroes, so before
        // the fix an ordinary `using` around a resolved KEK would have wiped it for every later
        // wrap in the process.
        var keyset = KekKeyset.CreateNew();
        var before = Read(keyset, keyset.CurrentKeyId);

        using (var scratch = new PinnedBuffer(KekSize))
        {
            keyset.CopyKeyTo(keyset.CurrentKeyId, scratch.Span);
        }

        Assert.Equal(before, Read(keyset, keyset.CurrentKeyId));
        Assert.NotEqual(new byte[KekSize], Read(keyset, keyset.CurrentKeyId));
    }

    [Fact]
    public void A_snapshot_is_a_deep_copy()
    {
        var keyset = KekKeyset.CreateNew();
        var id = keyset.CurrentKeyId;
        var before = Read(keyset, id);

        keyset.Snapshot()[id][0] ^= 0xFF;

        Assert.Equal(before, Read(keyset, id));
    }

    [Fact]
    public void The_constructor_does_not_alias_the_callers_dictionary()
    {
        var material = new byte[KekSize];
        material[0] = 0x11;
        var supplied = new Dictionary<string, byte[]> { ["kek-test"] = material };

        var keyset = new KekKeyset("kek-test", supplied);
        material[0] = 0x22;

        Assert.Equal(0x11, Read(keyset, "kek-test")[0]);
    }

    [Fact]
    public void With_new_version_shares_no_arrays_with_its_parent()
    {
        var parent = KekKeyset.CreateNew();
        var shared = parent.CurrentKeyId;
        var before = Read(parent, shared);

        var child = parent.WithNewVersion();
        var fromChild = Read(child, shared);
        fromChild[0] ^= 0xFF;

        Assert.Equal(before, Read(parent, shared));
        Assert.Equal(before, Read(child, shared));
    }

    [Fact]
    public void With_new_version_carries_every_prior_version_forward()
    {
        // Retention is load-bearing, not incidental: a DEK not yet re-wrapped must still unwrap,
        // which is what makes a partial rotation recoverable (phase-2.md, re-review H-D2).
        var first = KekKeyset.CreateNew();
        var second = first.WithNewVersion();
        var third = second.WithNewVersion();

        Assert.True(third.Contains(first.CurrentKeyId));
        Assert.True(third.Contains(second.CurrentKeyId));
        Assert.Equal(Read(first, first.CurrentKeyId), Read(third, first.CurrentKeyId));
        Assert.NotEqual(first.CurrentKeyId, third.CurrentKeyId);
    }

    [Fact]
    public void An_absent_version_is_reported_loudly_and_hands_out_nothing()
    {
        var keyset = KekKeyset.CreateNew();
        var destination = new byte[KekSize];

        Assert.False(keyset.Contains("kek-does-not-exist"));
        var ex = Assert.Throws<KeyNotFoundException>(
            () => keyset.CopyKeyTo("kek-does-not-exist", destination));
        Assert.Contains("kek-does-not-exist", ex.Message, StringComparison.Ordinal);

        // Nothing was written on the failure path.
        Assert.Equal(new byte[KekSize], destination);
    }

    [Fact]
    public void A_wrong_sized_destination_fails_rather_than_truncating()
    {
        // Silently filling a short buffer would produce ciphertext nothing can ever open.
        var keyset = KekKeyset.CreateNew();
        Assert.Throws<ArgumentException>(() => keyset.CopyKeyTo(keyset.CurrentKeyId, new byte[KekSize - 1]));
    }

    [Fact]
    public void ToString_does_not_render_key_material()
    {
        var material = new byte[KekSize];
        material.AsSpan().Fill(0xAB);
        var keyset = new KekKeyset("kek-test", new Dictionary<string, byte[]> { ["kek-test"] = material });

        var rendered = keyset.ToString();
        Assert.DoesNotContain(Convert.ToBase64String(material), rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToHexString(material), rendered, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<redacted>", rendered, StringComparison.Ordinal);
    }

    private static byte[] Read(KekKeyset keyset, string keyId)
    {
        var buffer = new byte[KekSize];
        keyset.CopyKeyTo(keyId, buffer);
        return buffer;
    }
}
