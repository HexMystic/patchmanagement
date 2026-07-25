using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Contracts.Modules;
using PatchManagement.Vault.KeyProviders;
using PatchManagement.Vault.Logging;
using PatchManagement.Vault.Services;

namespace PatchManagement.Vault;

/// <summary>
/// DI wiring for the Vault module (the <c>AddXModule()</c> half of the module convention). The key
/// provider is chosen purely by config — <c>VAULT_KEY_PROVIDER</c> (software | azure | aws |
/// hashicorp) — so swapping custody is a config change, not a code change to any caller
/// (phase-2.md exit criterion). Callers depend only on <see cref="ICredentialProvider"/> /
/// <see cref="ICredentialVault"/> and never see which provider is active.
/// </summary>
public static class VaultModule
{
    public static IServiceCollection AddVaultModule(this IServiceCollection services, IConfiguration configuration)
    {
        // NEVER #1 defense-in-depth: the redaction belt only helps if it is in the pipeline, so put
        // it there here rather than leaving it a class that only tests construct.
        services.AddSecretRedactingLogging();

        var providerName = configuration["VAULT_KEY_PROVIDER"] ?? "software";

        switch (providerName.Trim().ToLowerInvariant())
        {
            case "software":
                RegisterSoftwareProvider(services, configuration);
                break;
            case "azure":
                services.AddSingleton<IKeyProvider, AzureKeyVaultKeyProvider>();
                break;
            case "aws":
                services.AddSingleton<IKeyProvider, AwsKmsKeyProvider>();
                break;
            case "hashicorp":
                services.AddSingleton<IKeyProvider, HashiCorpVaultKeyProvider>();
                break;
            default:
                throw new InvalidOperationException(
                    $"Unknown VAULT_KEY_PROVIDER '{providerName}'. Expected: software | azure | aws | hashicorp.");
        }

        services.AddSingleton<IVaultActor, SystemVaultActor>();
        services.AddScoped<DataKeyService>();

        // One instance serves both the frozen read contract and the write contract.
        services.AddScoped<VaultCredentialProvider>();
        services.AddScoped<ICredentialProvider>(sp => sp.GetRequiredService<VaultCredentialProvider>());
        services.AddScoped<ICredentialVault>(sp => sp.GetRequiredService<VaultCredentialProvider>());

        // Singleton, not scoped: it runs off the HTTP path and CREATES its own per-tenant scopes via
        // ITenantScopeFactory, so a background job resolves it from the root with no ceremony. Being
        // scoped against the request-path context is what made it silently rotate nothing (review C1).
        services.AddSingleton<IKekRotationService, KekRotationService>();

        return services;
    }

    private static void RegisterSoftwareProvider(IServiceCollection services, IConfiguration configuration)
    {
        var kekSource = configuration["VAULT_SOFTWARE_KEK_SOURCE"] ?? "keyfile";

        switch (kekSource.Trim().ToLowerInvariant())
        {
            case "keyfile":
                var path = configuration["VAULT_SOFTWARE_KEK_FILE"]
                    ?? Path.Combine(AppContext.BaseDirectory, "vault", "kek.json");
                services.AddSingleton<IKekSource>(_ => new KeyFileKekSource(path));
                break;
            case "operator":
            case "tpm":
                throw new InvalidOperationException(
                    $"VAULT_SOFTWARE_KEK_SOURCE '{kekSource}' is declared in the threat model but not " +
                    "implemented in Phase 2. Use 'keyfile' (default).");
            default:
                throw new InvalidOperationException(
                    $"Unknown VAULT_SOFTWARE_KEK_SOURCE '{kekSource}'. Expected: keyfile | operator | tpm.");
        }

        services.AddSingleton<IKeyProvider, SoftwareKeyProvider>();
    }
}

/// <summary>
/// The discovery half of the convention: the host composition root finds this by reflection and
/// invokes it, so enabling the Vault module needs no edit to any shared registration file.
/// </summary>
internal sealed class VaultRegistrar : IModuleRegistrar
{
    public void Register(IServiceCollection services, IConfiguration configuration) =>
        services.AddVaultModule(configuration);
}
