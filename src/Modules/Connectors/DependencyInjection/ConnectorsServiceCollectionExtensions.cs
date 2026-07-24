using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Facts;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.WinRm;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.DependencyInjection;

/// <summary>
/// Wires the Connectors module. The concurrency governor and operation coordinator are singletons
/// (the connection budget is process-wide — the scaling wall; CLAUDE.md §2). Connectors are
/// singletons too so the SSH pool and its governed sessions are shared. Production swaps the
/// governor/coordinator for their Redis-backed equivalents here without touching connector code.
/// </summary>
public static class ConnectorsServiceCollectionExtensions
{
    public static IServiceCollection AddConnectorsModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ConnectorConcurrencyOptions>()
            .Bind(configuration.GetSection(ConnectorConcurrencyOptions.SectionName))
            .PostConfigure(o => o.Validate());

        services.TryAddSingleton<IConnectionGovernor, SemaphoreConnectionGovernor>();
        services.TryAddSingleton<IOperationCoordinator, KeyedOperationCoordinator>();

        // SSH — real, lab-tested transport. Connectors have internal ctors (encapsulation), so we
        // construct them with same-assembly factory lambdas rather than open-generic registration.
        services.TryAddSingleton<ISshSessionFactory, SshNetSessionFactory>();
        services.TryAddSingleton<SshConnectionPool>();
        services.AddSingleton<IEndpointConnector>(sp => new SshConnector(
            sp.GetRequiredService<ICredentialProvider>(),
            sp.GetRequiredService<ISshSessionFactory>(),
            sp.GetRequiredService<SshConnectionPool>(),
            sp.GetRequiredService<IConnectionGovernor>(),
            sp.GetRequiredService<IOperationCoordinator>(),
            sp.GetRequiredService<ILogger<SshConnector>>()));

        // WinRM — real WS-Man transport, integration-tested later (no Windows host in the dev lab).
        services.TryAddSingleton<IWinRmClient>(sp => new HttpWinRmClient(sp.GetService<IHttpClientFactory>()));
        services.AddSingleton<IEndpointConnector>(sp => new WinRmConnector(
            sp.GetRequiredService<ICredentialProvider>(),
            sp.GetRequiredService<IWinRmClient>(),
            sp.GetRequiredService<IConnectionGovernor>(),
            sp.GetRequiredService<IOperationCoordinator>(),
            sp.GetRequiredService<ILogger<WinRmConnector>>()));

        services.TryAddSingleton<IEndpointConnectorRegistry>(sp =>
            new EndpointConnectorRegistry(sp.GetServices<IEndpointConnector>()));
        services.TryAddSingleton<EndpointFactsCollector>();

        return services;
    }
}
