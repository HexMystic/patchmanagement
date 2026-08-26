using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Discovery.Sweep;

namespace PatchManagement.Discovery.DependencyInjection;

/// <summary>
/// Wires the Discovery module.
///
/// <para>Everything here is a <b>singleton</b>: the sweep holds no per-request state and consumes
/// no scoped service. That is deliberate rather than incidental — the moment it needs
/// <c>ICredentialProvider</c> (slice 3, inventory) it will have to become scoped for the same
/// captive-dependency reason the Connectors module documents, so the lifetime is worth revisiting
/// then instead of inheriting silently.</para>
/// </summary>
public static class DiscoveryServiceCollectionExtensions
{
    public static IServiceCollection AddDiscoveryModule(
        this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<DiscoverySweepOptions>()
            .Bind(configuration.GetSection(DiscoverySweepOptions.SectionName))
            .PostConfigure(o => o.Validate());

        services.AddOptions<DiscoverySecurityOptions>()
            .Bind(configuration.GetSection(DiscoverySecurityOptions.SectionName));

        services.TryAddSingleton<IPortProbe, TcpPortProbe>();
        services.TryAddSingleton<INetworkSweeper, NetworkSweeper>();

        return services;
    }
}
