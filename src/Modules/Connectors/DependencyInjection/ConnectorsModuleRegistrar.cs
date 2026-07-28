using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Modules;

namespace PatchManagement.Connectors.DependencyInjection;

/// <summary>
/// The module's <see cref="IModuleRegistrar"/>. The host's composition root discovers it by
/// reflection and calls <see cref="Register"/> — so adding the Connectors module never touches a
/// shared registration file (parallel worktrees cannot collide). Internal + parameterless so it is
/// instantiated via <c>Activator.CreateInstance(type, nonPublic: true)</c> and stays encapsulated.
/// </summary>
internal sealed class ConnectorsModuleRegistrar : IModuleRegistrar
{
    public void Register(IServiceCollection services, IConfiguration configuration) =>
        services.AddConnectorsModule(configuration);
}
