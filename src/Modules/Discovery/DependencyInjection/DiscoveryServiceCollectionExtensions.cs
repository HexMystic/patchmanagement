using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PatchManagement.Contracts.Discovery;
using Microsoft.Extensions.Logging;
using PatchManagement.Connectors;
using PatchManagement.Discovery.Inventory;
using PatchManagement.Discovery.Store;
using PatchManagement.Discovery.Sweep;
using PatchManagement.Persistence;

namespace PatchManagement.Discovery.DependencyInjection;

/// <summary>
/// Wires the Discovery module.
///
/// <para><b>The lifetime split, and why it is not arbitrary.</b> The sweep and its target policy
/// hold no per-request state and consume no scoped service, so they are <b>singletons</b>. The store
/// and the service that composes them are <b>scoped</b>, because the store consumes
/// <c>AppDbContext</c> — which the persistence module registers scoped and which carries the
/// per-request tenant through <c>RlsConnectionInterceptor</c>.</para>
///
/// <para>Registering the service as a singleton would capture that scoped context: a captive
/// dependency .NET's scope validation rejects outright, so the module would not resolve in the
/// shipped host at all. Resolving a fresh scope inside a singleton would not fix it either — the
/// tenant is ambient to the request, and a new scope would silently lose it, which is the
/// fail-closed hole ADR 0014 exists to close. The Connectors module documents the same split for
/// the same reason.</para>
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

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IPortProbe, TcpPortProbe>();
        services.TryAddSingleton<INetworkSweeper, NetworkSweeper>();

        // Scoped: AppDbContext is scoped and carries the request's tenant. See the class remarks.
        services.TryAddScoped<IDiscoveryStore>(sp => new DiscoveryStore(
            sp.GetRequiredService<AppDbContext>(),
            sp.GetRequiredService<TimeProvider>()));

        services.TryAddScoped<IInventoryService>(sp => new InventoryService(
            // The REGISTRY, not a connector: EndpointFactsCollector takes a single
            // IEndpointConnector and two are registered, so resolving it from DI hands it whichever
            // was registered last (WinRmConnector). See InventoryService's remarks.
            sp.GetRequiredService<IEndpointConnectorRegistry>(),
            sp.GetRequiredService<IDiscoveryStore>(),
            sp.GetRequiredService<ILogger<InventoryService>>()));

        services.TryAddScoped<IDiscoveryService>(sp => new DiscoveryService(
            sp.GetRequiredService<INetworkSweeper>(),
            sp.GetRequiredService<IDiscoveryStore>(),
            sp.GetRequiredService<ILogger<DiscoveryService>>()));

        return services;
    }
}
