using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Content.Abstractions;
using PatchManagement.Content.Connectors;
using PatchManagement.Content.Http;
using PatchManagement.Content.Ingestion;
using PatchManagement.Contracts.Content;
using PatchManagement.Contracts.Modules;

namespace PatchManagement.Content;

/// <summary>
/// DI wiring for the Content module (Phase 5). Registers the eight feed connectors, the idempotent
/// upsert store, the sync orchestrator, and the seams that let tests swap in recorded payloads.
/// Writes go through the <c>patchmgmt_content</c> role via <see cref="IContentConnectionFactory"/>,
/// resolved from <c>ConnectionStrings:Content</c> (ADR 0010).
/// </summary>
public static class ContentModule
{
    public static IServiceCollection AddContentModule(this IServiceCollection services, IConfiguration configuration)
    {
        // Public feeds — a bounded timeout keeps every fetch time-bound (NEVER #5). No auth handlers:
        // the feeds are public and this client must never carry a secret that could be logged (NEVER #1).
        services.AddHttpClient<IHttpContentFetcher, HttpContentFetcher>(c =>
        {
            c.Timeout = TimeSpan.FromMinutes(5);
            c.DefaultRequestHeaders.UserAgent.ParseAdd("PatchManagement-Content/1.0");
        });

        // wsusscn2 reads a LOCAL cab whose path comes from content_sources.endpoint, so the source is
        // constructed per sync rather than registered as a singleton with no path.
        services.AddTransient<Func<string, IWsusCatalogSource>>(_ => path => new DtfWsusCatalogSource(path));
        services.AddSingleton<IContentStore, ContentStore>();

        // Deferred throw: the API host does not resolve this unless a sync actually runs, so a host
        // that never ingests content need not configure the content connection string.
        services.AddSingleton<IContentConnectionFactory>(_ => new ContentConnectionFactory(
            configuration.GetConnectionString("Content")
            ?? throw new InvalidOperationException(
                "Missing connection string 'Content' (the patchmgmt_content ingestion role).")));

        services.AddTransient<ContentSyncService>();

        // Connectors — transient (they only hold stateless fetchers), also exposed as the
        // IContentConnector set so a scheduler can iterate feeds by Kind.
        AddConnector<NvdConnector>(services);
        AddConnector<KevConnector>(services);
        AddConnector<EpssConnector>(services);
        AddConnector<UsnConnector>(services);
        AddConnector<DebianDsaConnector>(services);
        AddConnector<RhsaConnector>(services);
        AddConnector<MsrcConnector>(services);
        AddConnector<Wsusscn2Connector>(services);

        return services;
    }

    private static void AddConnector<T>(IServiceCollection services)
        where T : class, IContentConnector
    {
        services.AddTransient<T>();
        services.AddTransient<IContentConnector>(sp => sp.GetRequiredService<T>());
    }
}

/// <summary>
/// Discovery half of the module convention: the host's composition root finds this by reflection
/// and invokes it, so enabling the Content module needs no edit to any shared registration file.
/// Internal + parameterless so it is instantiated via
/// <c>Activator.CreateInstance(type, nonPublic: true)</c> and stays encapsulated.
///
/// <para>Discovery only reaches this class if <c>PatchManagement.Content.dll</c> is in the host's
/// output directory, which requires a <c>ProjectReference</c> from <c>PatchManagement.Api</c>.
/// That reference is load-bearing and is asserted by <c>HostModuleDiscoveryTests</c> — this module
/// shipped without it once already.</para>
/// </summary>
internal sealed class ContentRegistrar : IModuleRegistrar
{
    public void Register(IServiceCollection services, IConfiguration configuration) =>
        services.AddContentModule(configuration);
}
