using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Modules;

namespace PatchManagement.Api;

/// <summary>
/// The single, rarely-touched composition root. It DISCOVERS every <see cref="IModuleRegistrar"/>
/// across the loaded PatchManagement.* assemblies by reflection and invokes it. Adding a module
/// (Phase 2 Vault, Phase 3 Connectors) means adding a registrar in THAT module's project — this
/// file never changes, so parallel worktrees cannot collide on it.
/// </summary>
public static class CompositionRoot
{
    public static IServiceCollection AddModules(this IServiceCollection services, IConfiguration configuration)
    {
        foreach (var assembly in LoadModuleAssemblies())
        {
            foreach (var type in assembly.GetTypes()
                         .Where(t => t is { IsAbstract: false, IsInterface: false }
                                     && typeof(IModuleRegistrar).IsAssignableFrom(t)))
            {
                // nonPublic: true allows internal registrar classes to stay encapsulated.
                var registrar = (IModuleRegistrar)Activator.CreateInstance(type, nonPublic: true)!;
                registrar.Register(services, configuration);
            }
        }

        return services;
    }

    private static IReadOnlyCollection<Assembly> LoadModuleAssemblies()
    {
        var byName = new Dictionary<string, Assembly>(StringComparer.Ordinal);

        void Consider(Assembly a)
        {
            var name = a.GetName().Name;
            if (name is not null && name.StartsWith("PatchManagement", StringComparison.Ordinal))
                byName.TryAdd(name, a);
        }

        // Already-loaded assemblies (fast path, and works regardless of the entry assembly —
        // e.g. under a test host where GetEntryAssembly() is the runner, not the API).
        foreach (var loaded in AppDomain.CurrentDomain.GetAssemblies())
            Consider(loaded);

        // Plus every PatchManagement.*.dll shipped alongside the app. Project references copy
        // their DLLs here, so a module the host references but never calls directly (the whole
        // point of discovery) is still found.
        foreach (var dll in Directory.EnumerateFiles(AppContext.BaseDirectory, "PatchManagement.*.dll"))
        {
            try { Consider(Assembly.LoadFrom(dll)); }
            catch (BadImageFormatException) { /* not a managed assembly — skip */ }
        }

        return byName.Values;
    }
}
