using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Content;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Contracts.Discovery;

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

    /// <summary>
    /// Same guard, for the Connectors module. Phase 3's WIP branch shipped the module without ever
    /// adding it to the solution or referencing it from the API — the identical defect the Vault hit
    /// at <c>a50d9ec</c>, where several review findings were latent purely because the module never
    /// loaded. One occurrence is an accident; the second is a pattern, so it gets a standing test.
    /// </summary>
    [Fact]
    public void Api_project_ships_the_connectors_module()
    {
        var deps = ApiDepsJsonPath();
        Assert.True(File.Exists(deps), $"Expected the API's build output at '{deps}'.");

        Assert.True(
            File.ReadAllText(deps).Contains("PatchManagement.Connectors", StringComparison.Ordinal),
            "PatchManagement.Api.deps.json does not list PatchManagement.Connectors, so the module "
            + "never reaches the host output and CompositionRoot cannot discover ConnectorsRegistrar "
            + "— endpoint operations would be unreachable in production. Add "
            + @"<ProjectReference Include=""..\..\Modules\Connectors\PatchManagement.Connectors.csproj"" /> "
            + $"to src/Host/Api/PatchManagement.Api.csproj.{Environment.NewLine}Checked: {deps}");
    }

    /// <summary>
    /// The behavioural half for Connectors. Asserted through <see cref="IEndpointConnector"/>, which
    /// lives in PatchManagement.Contracts, so this project still needs no reference to the module —
    /// the property that makes the test capable of failing (see the class remarks).
    /// </summary>
    [Fact]
    public void Real_host_container_resolves_the_connectors_module()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var scope = factory.Services.CreateScope();

        var connectors = scope.ServiceProvider.GetServices<IEndpointConnector>().ToList();

        Assert.True(connectors.Count > 0,
            "The real host's container has no IEndpointConnector — ConnectorsRegistrar was not "
            + "discovered by CompositionRoot, so the Connectors module is not loaded in the shipped app.");

        // Compared as a string so this project needs no compile-time reference to the module.
        Assert.Contains(
            connectors,
            c => c.GetType().Assembly.GetName().Name == "PatchManagement.Connectors");
    }

    /// <summary>
    /// Same guard, for the Content module — the THIRD occurrence of one defect. The Vault shipped
    /// unreferenced at <c>a50d9ec</c>, Phase 3's WIP repeated it, and Phase 5's WIP repeated it
    /// again: a complete module, eight feed connectors, an upsert store, 2,197 lines, and no path
    /// by which <c>ContentRegistrar</c> could ever be discovered in the shipped app.
    /// </summary>
    [Fact]
    public void Api_project_ships_the_content_module()
    {
        var deps = ApiDepsJsonPath();
        Assert.True(File.Exists(deps), $"Expected the API's build output at '{deps}'.");

        Assert.True(
            File.ReadAllText(deps).Contains("PatchManagement.Content", StringComparison.Ordinal),
            "PatchManagement.Api.deps.json does not list PatchManagement.Content, so the module "
            + "never reaches the host output and CompositionRoot cannot discover ContentRegistrar "
            + "— every feed connector would be unreachable in production. Add "
            + @"<ProjectReference Include=""..\..\Modules\Content\PatchManagement.Content.csproj"" /> "
            + $"to src/Host/Api/PatchManagement.Api.csproj.{Environment.NewLine}Checked: {deps}");
    }

    /// <summary>
    /// The behavioural half for Content. Asserted through <see cref="IContentConnector"/>, which
    /// ADR 0018 moved into PatchManagement.Contracts precisely so this project still needs no
    /// reference to the module — the property that makes the test capable of failing (see the class
    /// remarks).
    ///
    /// <para>Resolved deliberately as the connector SET rather than through <c>IContentStore</c> or
    /// <c>IContentConnectionFactory</c>: both depend on <c>ConnectionStrings:Content</c>, so
    /// resolving them would report a configuration gap in the language of a wiring gap. The set
    /// also proves all eight feeds registered, and — because the factory validates scopes — would
    /// catch the captive-dependency class of bug that sank the Connectors module.</para>
    /// </summary>
    [Fact]
    public void Real_host_container_resolves_the_content_module()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var scope = factory.Services.CreateScope();

        var connectors = scope.ServiceProvider.GetServices<IContentConnector>().ToList();

        Assert.True(connectors.Count > 0,
            "The real host's container has no IContentConnector — ContentRegistrar was not "
            + "discovered by CompositionRoot, so the Content module is not loaded in the shipped app.");

        // Compared as a string so this project needs no compile-time reference to the module.
        Assert.Contains(
            connectors,
            c => c.GetType().Assembly.GetName().Name == "PatchManagement.Content");

        // All eight feeds of the Phase 5 exit criteria, by Kind rather than by count — a count
        // passes for the wrong reason the moment a ninth connector is registered twice.
        Assert.Equal(
            new SortedSet<string>
            {
                Feeds.Nvd, Feeds.Kev, Feeds.Epss, Feeds.Usn,
                Feeds.Dsa, Feeds.Rhsa, Feeds.Msrc, Feeds.Wsusscn2,
            },
            new SortedSet<string>(connectors.Select(c => c.Kind), StringComparer.Ordinal));
    }

    /// <summary>
    /// Same guard, for the Discovery module — written before the module was referenced, which is
    /// the only order in which it can be trusted. This defect has shipped three times: the Vault at
    /// <c>a50d9ec</c>, Phase 3's WIP, and Phase 5's WIP, that last one a complete module with eight
    /// feed connectors and no path by which its registrar could ever be discovered. Phase 4 adds the
    /// fourth module, so the test exists before the <c>ProjectReference</c> does.
    /// </summary>
    [Fact]
    public void Api_project_ships_the_discovery_module()
    {
        var deps = ApiDepsJsonPath();
        Assert.True(File.Exists(deps), $"Expected the API's build output at '{deps}'.");

        Assert.True(
            File.ReadAllText(deps).Contains("PatchManagement.Discovery", StringComparison.Ordinal),
            "PatchManagement.Api.deps.json does not list PatchManagement.Discovery, so the module "
            + "never reaches the host output and CompositionRoot cannot discover "
            + "DiscoveryModuleRegistrar — network discovery would be unreachable in production. Add "
            + @"<ProjectReference Include=""..\..\Modules\Discovery\PatchManagement.Discovery.csproj"" /> "
            + $"to src/Host/Api/PatchManagement.Api.csproj.{Environment.NewLine}Checked: {deps}");
    }

    /// <summary>
    /// The behavioural half for Discovery, asserted through <see cref="INetworkSweeper"/> — which
    /// lives in PatchManagement.Contracts for exactly this reason (see the class remarks): a test
    /// project that referenced the module would copy its DLL into its own output, discovery would
    /// succeed on that copy, and this test would pass while the API shipped without the module.
    /// </summary>
    [Fact]
    public void Real_host_container_resolves_the_discovery_module()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var scope = factory.Services.CreateScope();

        var sweeper = scope.ServiceProvider.GetService<INetworkSweeper>();

        Assert.True(sweeper is not null,
            "The real host's container has no INetworkSweeper — DiscoveryModuleRegistrar was not "
            + "discovered by CompositionRoot, so the Discovery module is not loaded in the shipped app.");

        // Compared as a string so this project needs no compile-time reference to the module.
        Assert.Equal("PatchManagement.Discovery", sweeper.GetType().Assembly.GetName().Name);
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
