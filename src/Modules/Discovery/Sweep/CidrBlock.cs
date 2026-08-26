using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace PatchManagement.Discovery.Sweep;

/// <summary>
/// A bounded IPv4 CIDR block, parsed from text and enumerable as addresses.
///
/// <para><b>IPv4 only, and IPv6 is refused by name rather than skipped.</b> A sweep works by
/// enumerating every address in a range, and an IPv6 subnet is not enumerable — the smallest block
/// commonly assigned, a <c>/64</c>, holds 18 quintillion addresses. There is no bound that makes
/// that tractable, so accepting the syntax and quietly probing a prefix of it would report an
/// estate's contents from an arbitrary sliver. Refusing by name is the same discipline the
/// connector applies to multi-hop chains: silently doing something adjacent to what was asked is
/// the worst available outcome for a misconfiguration.</para>
///
/// <para><b>Every address in the block is enumerated, including the network and broadcast
/// addresses.</b> Skipping them is a convention, not a rule — RFC 3021 point-to-point links use
/// both addresses of a <c>/31</c>, and hosts do sit on subnet-zero addresses in practice. This
/// product's claim in Phase 4 is that it surfaces the machines other tools miss, so a discovery
/// sweep with a built-in blind spot would undercut the feature it belongs to. A probe to an address
/// nothing answers on simply fails, which costs one timeout.</para>
/// </summary>
internal sealed class CidrBlock
{
    private readonly uint _network;

    private CidrBlock(uint network, int prefixLength, string text)
    {
        _network = network;
        PrefixLength = prefixLength;
        Text = text;
    }

    public int PrefixLength { get; }

    /// <summary>The original text, so a refusal can name the range the operator actually typed.</summary>
    public string Text { get; }

    /// <summary>Addresses in the block. A <c>/32</c> is 1; a <c>/0</c> would be 2^32.</summary>
    public long HostCount => 1L << (32 - PrefixLength);

    /// <summary>Lowest address in the block.</summary>
    public IPAddress NetworkAddress => FromUInt32(_network);

    /// <summary>
    /// Highest address in the block. Exposed alongside <see cref="NetworkAddress"/> so containment
    /// can be decided in two comparisons — <c>Addresses().Last()</c> would walk 65,536 addresses to
    /// answer a question about the shape of the block rather than its contents.
    /// </summary>
    public IPAddress BroadcastAddress => FromUInt32(_network + (uint)(HostCount - 1));

    /// <summary>
    /// True when every address of <paramref name="other"/> lies inside this block. Both are aligned
    /// CIDR blocks, so the two endpoints settle it.
    /// </summary>
    public bool Contains(CidrBlock other) =>
        Contains(other.NetworkAddress) && Contains(other.BroadcastAddress);

    public IEnumerable<IPAddress> Addresses()
    {
        var count = HostCount;
        for (long i = 0; i < count; i++)
        {
            yield return FromUInt32(_network + (uint)i);
        }
    }

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        return (ToUInt32(address) & MaskFor(PrefixLength)) == _network;
    }

    /// <summary>
    /// Parses <paramref name="text"/> as an IPv4 CIDR block, or explains why it is not one.
    ///
    /// <para>A bare address with no prefix is accepted as a <c>/32</c>: "sweep this one host" is a
    /// real request, and making an operator write the suffix buys nothing.</para>
    ///
    /// <para><paramref name="maxHosts"/> is enforced here rather than by the caller so that no code
    /// path can obtain an unbounded block — an oversized range never becomes a
    /// <see cref="CidrBlock"/> at all, instead of becoming one that callers are trusted to check.</para>
    /// </summary>
    public static bool TryParse(
        string? text, long maxHosts, [NotNullWhen(true)] out CidrBlock? block, out string? reason)
    {
        block = null;
        reason = null;

        if (string.IsNullOrWhiteSpace(text))
        {
            reason = "Range is empty.";
            return false;
        }

        var trimmed = text.Trim();
        var slash = trimmed.IndexOf('/');
        var addressPart = slash < 0 ? trimmed : trimmed[..slash];

        if (!IPAddress.TryParse(addressPart, out var address))
        {
            reason = "Not a valid IP address or CIDR block.";
            return false;
        }

        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            reason = "IPv6 ranges are not sweepable - a /64 holds 1.8e19 addresses, so no bound "
                + "makes enumerating one meaningful. Refused rather than truncated.";
            return false;
        }

        var prefixLength = 32;
        if (slash >= 0)
        {
            var prefixPart = trimmed[(slash + 1)..];
            if (!int.TryParse(prefixPart, out prefixLength) || prefixLength is < 0 or > 32)
            {
                reason = "Prefix length must be an integer within 0-32.";
                return false;
            }
        }

        var network = ToUInt32(address) & MaskFor(prefixLength);
        var hostCount = 1L << (32 - prefixLength);

        if (hostCount > maxHosts)
        {
            reason = $"Range expands to {hostCount:N0} addresses, above the configured cap of "
                + $"{maxHosts:N0}. Refused rather than truncated - sweeping a prefix of a range and "
                + "reporting success would describe the estate from an arbitrary sliver of it.";
            return false;
        }

        block = new CidrBlock(network, prefixLength, trimmed);
        return true;
    }

    private static uint MaskFor(int prefixLength) =>
        prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);

    private static uint ToUInt32(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[4];
        address.TryWriteBytes(bytes, out _);
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static IPAddress FromUInt32(uint value) =>
        new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });
}
