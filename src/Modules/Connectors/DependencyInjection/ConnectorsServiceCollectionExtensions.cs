using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Facts;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.WinRm;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.DependencyInjection;

/// <summary>
/// Wires the Connectors module. Production swaps the governor/coordinator for their Redis-backed
/// equivalents here without touching connector code.
///
/// <para><b>The lifetime split, and why it is not arbitrary.</b> Everything that carries the
/// process-wide connection budget — the governor, the operation coordinator, the session factory and
/// the SSH pool — is a <b>singleton</b>: that budget is the scaling wall at 10,000 endpoints
/// (CLAUDE.md §2), and a per-request pool would reuse nothing and cap nothing.</para>
///
/// <para>The connectors themselves are <b>scoped</b>, because they consume
/// <see cref="ICredentialProvider"/>, which the vault registers scoped (it depends on the
/// per-request <c>AppDbContext</c> and tenant context). Registering the connectors as singletons
/// made them capture a scoped service — a captive dependency that .NET's scope validation rejects
/// outright, so the module could not resolve in the shipped host at all. Resolving a fresh scope
/// inside a singleton would not have fixed it either: the tenant context is ambient to the request,
/// and a new scope would silently lose it, which is the fail-closed hole ADR 0014 exists to close.</para>
///
/// <para>So the expensive shared state is process-wide and the tenant-scoped composition is
/// per-request, which is what both constraints actually demand.</para>
/// </summary>
public static class ConnectorsServiceCollectionExtensions
{
    public static IServiceCollection AddConnectorsModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ConnectorConcurrencyOptions>()
            .Bind(configuration.GetSection(ConnectorConcurrencyOptions.SectionName))
            .PostConfigure(o => o.Validate());

        services.AddOptions<ConnectorTimeoutOptions>()
            .Bind(configuration.GetSection(ConnectorTimeoutOptions.SectionName))
            .PostConfigure(o => o.Validate());

        services.AddOptions<ConnectorSecurityOptions>()
            .Bind(configuration.GetSection(ConnectorSecurityOptions.SectionName));

        // Registered so tests can substitute a fake clock through the container rather than only
        // through a hand-built connector.
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<IConnectionGovernor, SemaphoreConnectionGovernor>();
        services.TryAddSingleton<IOperationCoordinator, KeyedOperationCoordinator>();

        // SSH — real, lab-tested transport. Connectors have internal ctors (encapsulation), so we
        // construct them with same-assembly factory lambdas rather than open-generic registration.
        services.TryAddSingleton<ISshSessionFactory>(sp => new SshNetSessionFactory(
            sp.GetRequiredService<IOptions<ConnectorSecurityOptions>>().Value,
            sp.GetRequiredService<IOptions<ConnectorTimeoutOptions>>().Value));
        services.TryAddSingleton<SshConnectionPool>();
        services.AddScoped<IEndpointConnector>(sp => new SshConnector(
            sp.GetRequiredService<ICredentialProvider>(),
            sp.GetRequiredService<ISshSessionFactory>(),
            sp.GetRequiredService<SshConnectionPool>(),
            sp.GetRequiredService<IConnectionGovernor>(),
            sp.GetRequiredService<IOperationCoordinator>(),
            sp.GetRequiredService<ILogger<SshConnector>>(),
            sp.GetRequiredService<IOptions<ConnectorTimeoutOptions>>().Value,
            sp.GetRequiredService<TimeProvider>()));

        // WinRM — real WS-Man transport, integration-tested later (no Windows host in the dev lab).
        // No IHttpClientFactory: a pooled, named client cannot carry per-target credentials, and the
        // previous registration handed one in — which made every WinRM call unauthenticated.
        services.TryAddSingleton<IWinRmClient>(_ => new HttpWinRmClient());
        services.AddScoped<IEndpointConnector>(sp => new WinRmConnector(
            sp.GetRequiredService<ICredentialProvider>(),
            sp.GetRequiredService<IWinRmClient>(),
            sp.GetRequiredService<IConnectionGovernor>(),
            sp.GetRequiredService<IOperationCoordinator>(),
            sp.GetRequiredService<ILogger<WinRmConnector>>()));

        // Scoped, following the connectors they compose over — a singleton registry would capture
        // the scoped connectors and reintroduce the same captive dependency one level up.
        services.TryAddScoped<IEndpointConnectorRegistry>(sp =>
            new EndpointConnectorRegistry(sp.GetServices<IEndpointConnector>()));
        services.TryAddScoped<EndpointFactsCollector>();

        return services;
    }
}
