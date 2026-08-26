using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Modules;

namespace PatchManagement.Discovery.DependencyInjection;

/// <summary>
/// The module's <see cref="IModuleRegistrar"/>. The host's composition root discovers it by
/// reflection and calls <see cref="Register"/>, so adding Discovery never touches a shared
/// registration file. Internal + parameterless so it is instantiated via
/// <c>Activator.CreateInstance(type, nonPublic: true)</c> and stays encapsulated.
/// </summary>
internal sealed class DiscoveryModuleRegistrar : IModuleRegistrar
{
    public void Register(IServiceCollection services, IConfiguration configuration) =>
        services.AddDiscoveryModule(configuration);
}
