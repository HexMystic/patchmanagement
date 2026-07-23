using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace PatchManagement.Contracts.Modules;

/// <summary>
/// The module DI convention. Each feature module ships an <c>AddXModule()</c> extension AND
/// an internal <c>IModuleRegistrar</c> that calls it. The host's single, rarely-touched
/// composition root discovers all registrars by reflection and invokes them — so adding a
/// module (Phase 2 Vault, Phase 3 Connectors) means adding a class in THAT module's project,
/// never editing a shared registration file. Parallel worktrees therefore cannot collide on
/// one file.
/// </summary>
public interface IModuleRegistrar
{
    /// <summary>Register this module's services.</summary>
    void Register(IServiceCollection services, IConfiguration configuration);
}
