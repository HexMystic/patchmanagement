using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace PatchManagement.Vault.Logging;

/// <summary>
/// Puts <see cref="SecretRedactingLoggerProvider"/> into the host's logging pipeline by DECORATING
/// every <see cref="ILoggerProvider"/> registered so far: each descriptor is replaced with one that
/// builds the original provider and wraps it. A provider cannot intercept its siblings, so wrapping
/// each registration is what makes the belt real rather than a class only tests construct.
///
/// <para>Two ordering facts follow from "registered so far". Providers added AFTER the Vault module
/// are not wrapped — in the host this is safe because <c>WebApplication.CreateBuilder</c> registers
/// the default providers before the composition root runs. And because the replacement descriptor
/// carries a factory rather than an implementation type, a later <c>TryAddEnumerable</c> for the
/// same provider type no longer dedupes against it, so a subsequent <c>AddConsole()</c> would add a
/// second, unwrapped console provider.</para>
/// </summary>
public static class SecretRedactionRegistration
{
    /// <summary>Category prefix the belt applies to — the Vault module's own logging.</summary>
    public const string VaultCategoryPrefix = "PatchManagement.Vault.";

    /// <summary>Decorates the currently-registered logger providers. Safe to call more than once.</summary>
    public static IServiceCollection AddSecretRedactingLogging(this IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(RedactionMarker))) return services;
        services.AddSingleton<RedactionMarker>();

        for (var i = 0; i < services.Count; i++)
        {
            var original = services[i];
            if (original.ServiceType != typeof(ILoggerProvider)) continue;

            services[i] = ServiceDescriptor.Describe(
                typeof(ILoggerProvider),
                sp => new SecretRedactingLoggerProvider(
                    Instantiate(sp, original),
                    category => category.StartsWith(VaultCategoryPrefix, StringComparison.Ordinal)),
                original.Lifetime);
        }

        return services;
    }

    /// <summary>Builds the provider the original descriptor described, in whichever form it took.</summary>
    private static ILoggerProvider Instantiate(IServiceProvider sp, ServiceDescriptor descriptor)
    {
        if (descriptor.ImplementationInstance is ILoggerProvider instance) return instance;
        if (descriptor.ImplementationFactory is { } factory) return (ILoggerProvider)factory(sp);
        return (ILoggerProvider)ActivatorUtilities.CreateInstance(sp, descriptor.ImplementationType!);
    }

    /// <summary>Presence in the collection marks the decoration as already applied.</summary>
    private sealed class RedactionMarker;
}
