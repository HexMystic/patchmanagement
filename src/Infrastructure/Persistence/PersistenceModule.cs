using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Auditing;
using PatchManagement.Contracts.Modules;
using PatchManagement.Persistence.Auditing;
using PatchManagement.Persistence.Rls;

namespace PatchManagement.Persistence;

/// <summary>DI wiring for the Persistence module (the <c>AddXModule()</c> half of the convention).</summary>
public static class PersistenceModule
{
    public static IServiceCollection AddPersistence(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("App")
            ?? throw new InvalidOperationException("Missing connection string 'App' (the restricted app-role connection).");

        // Tenant context + RLS interceptor are scoped so each request scopes its own connections.
        services.AddScoped<TenantContextAccessor>();
        services.AddScoped<ITenantContext>(sp => sp.GetRequiredService<TenantContextAccessor>());
        services.AddScoped<RlsConnectionInterceptor>();

        services.AddDbContext<AppDbContext>((sp, options) =>
            options
                .UseNpgsql(connectionString)
                .AddInterceptors(sp.GetRequiredService<RlsConnectionInterceptor>())
                .UseSnakeCaseNamingConvention());

        services.AddScoped<IAuditLog, EfAuditLog>();

        return services;
    }
}

/// <summary>
/// The discovery half of the convention: the host's composition root finds this by reflection
/// and calls it — no shared registration file to edit when modules are added in parallel.
/// </summary>
internal sealed class PersistenceRegistrar : IModuleRegistrar
{
    public void Register(IServiceCollection services, IConfiguration configuration) =>
        services.AddPersistence(configuration);
}
