using System.Net;
using PatchManagement.Discovery.Sweep;

namespace PatchManagement.Discovery.Tests.Sweep;

/// <summary>
/// Range parsing and enumeration. The cap is applied inside <see cref="CidrBlock.TryParse"/> rather
/// than by callers, so these tests are also what proves an unbounded block cannot be constructed at
/// all — not merely that nobody currently constructs one.
/// </summary>
public sealed class CidrBlockTests
{
    private const long Cap = 65_536;

    [Theory]
    [InlineData("127.0.0.1/32", 1)]
    [InlineData("127.0.0.0/31", 2)]
    [InlineData("127.0.0.0/30", 4)]
    [InlineData("10.20.30.0/24", 256)]
    public void A_block_expands_to_two_to_the_host_bits(string text, int expected)
    {
        Assert.True(CidrBlock.TryParse(text, Cap, out var block, out _));
        Assert.Equal(expected, block.HostCount);
        Assert.Equal(expected, block.Addresses().Count());
    }

    [Fact]
    public void A_bare_address_is_a_single_host()
    {
        Assert.True(CidrBlock.TryParse("192.0.2.7", Cap, out var block, out _));

        Assert.Equal(32, block.PrefixLength);
        Assert.Equal("192.0.2.7", Assert.Single(block.Addresses()).ToString());
    }

    /// <summary>Host bits below the prefix are masked off, so 10.1.2.3/24 is the 10.1.2.0 block.</summary>
    [Fact]
    public void Host_bits_below_the_prefix_are_masked_off()
    {
        Assert.True(CidrBlock.TryParse("10.1.2.3/24", Cap, out var block, out _));

        Assert.Equal("10.1.2.0", block.Addresses().First().ToString());
        Assert.Equal("10.1.2.255", block.Addresses().Last().ToString());
    }

    [Fact]
    public void Enumeration_includes_the_network_and_broadcast_addresses()
    {
        Assert.True(CidrBlock.TryParse("192.0.2.0/30", Cap, out var block, out _));

        var addresses = block.Addresses().Select(a => a.ToString()).ToList();

        Assert.Equal(["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"], addresses);
    }

    [Fact]
    public void An_ipv6_block_is_rejected_with_a_reason_naming_ipv6()
    {
        Assert.False(CidrBlock.TryParse("2001:db8::/64", Cap, out _, out var reason));

        Assert.NotNull(reason);
        Assert.Contains("IPv6", reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-cidr")]
    [InlineData("999.1.1.1/24")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.0/abc")]
    public void Uninterpretable_text_is_rejected_with_a_reason(string text)
    {
        Assert.False(CidrBlock.TryParse(text, Cap, out var block, out var reason));

        Assert.Null(block);
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public void A_block_above_the_cap_cannot_be_constructed()
    {
        Assert.False(CidrBlock.TryParse("10.0.0.0/8", Cap, out var block, out var reason));

        Assert.Null(block);
        Assert.Contains("cap", reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_block_exactly_at_the_cap_is_accepted()
    {
        Assert.True(CidrBlock.TryParse("10.0.0.0/16", Cap, out var block, out _));

        Assert.Equal(Cap, block.HostCount);
    }

    [Fact]
    public void Containment_is_by_network_not_by_text()
    {
        Assert.True(CidrBlock.TryParse("192.168.1.0/24", Cap, out var block, out _));

        Assert.True(block.Contains(IPAddress.Parse("192.168.1.0")));
        Assert.True(block.Contains(IPAddress.Parse("192.168.1.255")));
        Assert.False(block.Contains(IPAddress.Parse("192.168.2.0")));
        Assert.False(block.Contains(IPAddress.Parse("2001:db8::1")));
    }

    /// <summary>
    /// The whole address space is representable, so a policy entry of 0.0.0.0/0 means what it says.
    /// It is only ever reachable by an operator writing it explicitly — the default permits nothing.
    /// </summary>
    [Fact]
    public void A_zero_prefix_covers_the_whole_ipv4_space()
    {
        Assert.True(CidrBlock.TryParse("0.0.0.0/0", long.MaxValue, out var block, out _));

        Assert.Equal(4_294_967_296L, block.HostCount);
        Assert.True(block.Contains(IPAddress.Parse("8.8.8.8")));
    }
}
