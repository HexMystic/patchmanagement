using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using PatchManagement.Connectors;

namespace PatchManagement.Discovery.Sweep;

/// <summary>
/// <see cref="IConnectionTargetPolicy"/> over the <b>same</b> allowlist the sweep honours
/// (<see cref="DiscoverySecurityOptions.AllowedTargets"/>) — one declaration of scope, consulted by
/// both the thing that finds hosts and the thing that connects to them.
///
/// <para><b>An empty allowlist means unrestricted here, and means nothing-permitted for the sweep.
/// The asymmetry is deliberate.</b> A sweep contacts addresses <em>unbidden</em> — nobody named
/// them, a CIDR did — so an undeclared scope must permit nothing or the product would probe an
/// estate no one authorised. A connection is the opposite: an operator named this endpoint. An
/// undeclared scope therefore means "this deployment has no connector-target policy", not "refuse
/// every connection", which would break every production deployment that never declared sweep
/// ranges. Where a scope IS declared — as the dev environment declares loopback — connections honour
/// it too, and that is what closes the D-306 hole.</para>
/// </summary>
internal sealed class ConnectionTargetPolicy : IConnectionTargetPolicy
{
    private readonly DiscoveryTargetPolicy _policy;
    private readonly bool _hasDeclaredScope;

    /// <summary>
    /// Bounds the DNS lookup. A policy check that could hang would be a way to stall every
    /// connection, and NEVER #5 applies to this path as much as to the connect it precedes.
    /// </summary>
    private static readonly TimeSpan ResolutionBudget = TimeSpan.FromSeconds(5);

    public ConnectionTargetPolicy(DiscoverySecurityOptions options, ILogger<ConnectionTargetPolicy> logger)
    {
        _policy = new DiscoveryTargetPolicy(options, logger);
        _hasDeclaredScope = options.AllowedTargets.Count > 0;
    }

    public async Task<string?> RefusalReasonAsync(string host, CancellationToken ct)
    {
        if (!_hasDeclaredScope) return null;

        IPAddress[] addresses;
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(ResolutionBudget);

            addresses = IPAddress.TryParse(host, out var literal)
                ? [literal]
                : await Dns.GetHostAddressesAsync(host, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            // Fail closed. An address we cannot determine is an address we cannot place inside the
            // declared scope, and guessing in the permissive direction is how a guard becomes
            // decoration.
            return $"'{host}' could not be resolved, so it cannot be shown to fall inside "
                   + "Discovery:Security:AllowedTargets. Refusing rather than contacting an address "
                   + "this deployment has not declared.";
        }

        if (addresses.Length == 0)
            return $"'{host}' resolved to no addresses, so it cannot be placed inside Discovery:Security:AllowedTargets.";

        // EVERY resolved address must be in scope, not merely one. A name that resolves both inside
        // and outside the declared range is a name that can route out of it, and which address gets
        // used is not ours to predict.
        foreach (var address in addresses)
        {
            var candidate = Normalise(address);

            if (candidate is null)
            {
                return $"'{host}' resolves to {address}, which is IPv6 and cannot be expressed in "
                       + "Discovery:Security:AllowedTargets (IPv4 CIDR only). Refusing rather than "
                       + "treating an address the policy cannot describe as permitted.";
            }

            if (!_policy.PermitsAddress(candidate))
            {
                return $"'{host}' resolves to {candidate}, which is not inside any entry of "
                       + "Discovery:Security:AllowedTargets. CLAUDE.md NEVER #4: this deployment may "
                       + "only contact the addresses it has declared.";
            }
        }

        return null;
    }

    /// <summary>
    /// The IPv4 address to test, or <c>null</c> when the address cannot be expressed in an IPv4
    /// allowlist at all.
    ///
    /// <para>Loopback is mapped rather than rejected because it is a genuine equivalence — <c>::1</c>
    /// and <c>127.0.0.1</c> are both "this machine" — and because on Windows <c>localhost</c>
    /// resolves to <c>::1</c> first. A policy that rejected everything it could not express would
    /// refuse the dev lab's own published fleet, which is the one thing it must permit.</para>
    /// </summary>
    private static IPAddress? Normalise(IPAddress address) => address.AddressFamily switch
    {
        AddressFamily.InterNetwork => address,
        AddressFamily.InterNetworkV6 when IPAddress.IsLoopback(address) => IPAddress.Loopback,
        AddressFamily.InterNetworkV6 when address.IsIPv4MappedToIPv6 => address.MapToIPv4(),
        _ => null,
    };
}
