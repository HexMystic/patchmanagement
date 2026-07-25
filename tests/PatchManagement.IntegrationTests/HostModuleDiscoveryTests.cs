using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Proves the Vault module is reachable in the SHIPPED application, not merely when a test hands
/// it the assembly.
///
/// <para>The trap this is built to avoid: <c>CompositionRoot.LoadModuleAssemblies</c> scans
/// <c>AppContext.BaseDirectory</c>, which under a test host is the TEST project's output folder. A
/// test project that referenced the Vault directly would put <c>PatchManagement.Vault.dll</c>
/// there, discovery would succeed on that copy, and the test would pass while the API still
/// shipped without the module — the exact defect being fixed. So this project deliberately does
/// NOT reference the Vault, and the assertions below go through
/// <see cref="ICredentialProvider"/>, which lives in PatchManagement.Contracts.</para>
///
/// <para>No <c>[Collection]</c> attribute: this class needs no database. AddDbContext's UseNpgsql
/// sits in a lazy options lambda and no query is executed here.</para>
/// </summary>
public sealed class HostModuleDiscoveryTests
{
    /// <summary>
    /// The primary guard, and the one that owes nothing to the test harness: the API's OWN
    /// dependency graph must name the Vault. If it does not, the DLL never reaches the host output
    /// and <c>VaultRegistrar</c> cannot be discovered in production, whatever a test container shows.
    /// </summary>
    [Fact]
    public void Api_project_ships_the_vault_module()
    {
        var deps = ApiDepsJsonPath();
        Assert.True(File.Exists(deps), $"Expected the API's build output at '{deps}'.");

        Assert.True(
            File.ReadAllText(deps).Contains("PatchManagement.Vault", StringComparison.Ordinal),
            "PatchManagement.Api.deps.json does not list PatchManagement.Vault, so the Vault assembly "
            + "never reaches the host output and CompositionRoot cannot discover VaultRegistrar — the "
            + "module would be unreachable in production. Add "
            + @"<ProjectReference Include=""..\..\Modules\Vault\PatchManagement.Vault.csproj"" /> to "
            + $"src/Host/Api/PatchManagement.Api.csproj.{Environment.NewLine}Checked: {deps}");
    }

    /// <summary>
    /// The behavioural half: hosting the real <c>Program</c> must produce a container in which the
    /// vault is registered, via genuine composition-root discovery rather than a direct
    /// AddVaultModule call.
    /// </summary>
    [Fact]
    public void Real_host_container_resolves_the_vault_module()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var scope = factory.Services.CreateScope();

        var credentials = scope.ServiceProvider.GetService<ICredentialProvider>();
        Assert.True(credentials is not null,
            "The real host's container has no ICredentialProvider — VaultRegistrar was not discovered "
            + "by CompositionRoot, so the Vault module is not loaded in the shipped app.");

        // The binding must come from the Vault assembly itself. Compared as a string so this project
        // needs no compile-time reference to the Vault (see the class remarks).
        Assert.Equal("PatchManagement.Vault", credentials!.GetType().Assembly.GetName().Name);

        // And the NEVER #1 redaction belt is live in the host pipeline, not just in module tests.
        Assert.True(
            factory.Services.GetServices<ILoggerProvider>()
                .Any(p => p.GetType().Name == "SecretRedactingLoggerProvider"),
            "No SecretRedactingLoggerProvider in the host's logger providers — the redaction belt is "
            + "not active in the shipped app.");
    }

    /// <summary>Path to the API's own build output, matching this test run's configuration.</summary>
    private static string ApiDepsJsonPath()
    {
        // Test output layout: .../tests/PatchManagement.IntegrationTests/bin/<config>/<tfm>/
        var baseDir = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
        var tfm = baseDir.Name;
        var configuration = baseDir.Parent?.Name
            ?? throw new InvalidOperationException($"Unexpected test output layout: '{AppContext.BaseDirectory}'.");

        return Path.Combine(
            RepoRoot().FullName, "src", "Host", "Api", "bin", configuration, tfm,
            "PatchManagement.Api.deps.json");
    }

    private static DirectoryInfo RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "PatchManagement.sln")))
            dir = dir.Parent;

        return dir ?? throw new InvalidOperationException(
            $"Could not locate PatchManagement.sln walking up from '{AppContext.BaseDirectory}'.");
    }
}
