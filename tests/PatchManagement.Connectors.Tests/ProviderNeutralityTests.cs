using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Connectors.DependencyInjection;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport;
using PatchManagement.TestSupport.Conventions;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests;

/// <summary>
/// Exit criterion (a): the connector is provider-neutral. ADR 0003 says direct-vs-bastion is a
/// property of the target configuration, and that the connector never knows whether it is talking to
/// on-prem, Azure, AWS or GCP. These turn that into something the build can check.
/// </summary>
public sealed class ProviderNeutralityTests
{
    /// <summary>
    /// The assembly declaring <see cref="IEndpointConnector"/> must not drag in a protocol library.
    ///
    /// <para>This is the machine-checkable form of "consumers depend on the abstraction, not the
    /// implementation". Phase 4 (Discovery) and Phase 8 (Deployment) both consume this interface; if
    /// it ships in the same assembly as SSH.NET, every consumer inherits an SSH client it has no use
    /// for, and the host-module discovery guard cannot assert the module loads without referencing
    /// it — which is exactly the check that caught the Phase 2 missing-reference bug.</para>
    /// </summary>
    [Fact]
    public void Contracts_assembly_declaring_the_connector_does_not_reference_a_protocol_library()
    {
        var declaring = typeof(IEndpointConnector).Assembly;

        var offenders = declaring.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => n.Contains("SshNet", StringComparison.OrdinalIgnoreCase)
                        || n.Contains("Renci", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"'{declaring.GetName().Name}' declares IEndpointConnector but references " +
            $"[{string.Join(", ", offenders)}]. The contract surface must live in an assembly that " +
            "carries no transport dependency.");
    }

    /// <summary>
    /// The container must hand back the connector matching the target's protocol.
    ///
    /// <para>Both connectors register against <c>IEndpointConnector</c>, so a plain resolve returns
    /// whichever was registered last — WinRM — for <em>every</em> protocol. Anything resolving the
    /// bare interface would therefore drive Linux hosts over WS-Man and fail in a way that looks
    /// like a network problem.</para>
    /// </summary>
    [Fact]
    public async Task The_registry_resolves_a_different_connector_per_protocol()
    {
        await using var provider = BuildContainer();
        using var scope = provider.CreateScope();

        var registry = scope.ServiceProvider.GetRequiredService<IEndpointConnectorRegistry>();

        var ssh = registry.For(EndpointProtocol.Ssh);
        var winrm = registry.For(EndpointProtocol.WinRm);

        Assert.Equal(EndpointProtocol.Ssh, ssh.Protocol);
        Assert.Equal(EndpointProtocol.WinRm, winrm.Protocol);
        Assert.NotSame(ssh, winrm);
    }

    [Fact]
    public async Task An_unregistered_protocol_is_refused_by_name_rather_than_defaulted()
    {
        await using var provider = BuildContainer();
        using var scope = provider.CreateScope();
        var registry = scope.ServiceProvider.GetRequiredService<IEndpointConnectorRegistry>();

        // Falling back to "some connector" is how a Linux host ends up being probed over WinRM.
        var ex = Assert.Throws<NotSupportedException>(() => registry.For((EndpointProtocol)999));
        Assert.Contains("999", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// ADR 0003 turned into something the build can check: no cloud vocabulary anywhere in the
    /// connector or its contract surface. A connector that knows it is talking to Azure has already
    /// lost the property the ADR is protecting.
    /// </summary>
    [Fact]
    public void No_cloud_provider_vocabulary_appears_in_the_connector_or_its_contracts()
    {
        var pattern = new Regex(
            @"\b(azure|aws|ec2|gcp|google\s*cloud|hyper-?v|vsphere|vmware|digitalocean)\b",
            RegexOptions.IgnoreCase);

        string[] directories =
        [
            RepoPaths.Source("src", "Modules", "Connectors"),
            RepoPaths.Source("src", "Shared", "Contracts", "Connectors"),
        ];

        // Comments are excluded on purpose. The rule ADR 0003 states is that no cloud provider may
        // influence connector BEHAVIOUR — not that the word may never be written down. BastionHop's
        // own doc says a hop "may be an Azure Bastion, an AWS SSM proxy, an on-prem jump box, or
        // anything else", which is the ADR's argument rather than a violation of it. Flagging prose
        // that explains the rule would teach people to delete the explanation.
        var hits = directories
            .SelectMany(d => SourceScanner.Scan(d, pattern, ignore: (_, _, text) => IsComment(text)))
            .ToList();

        // Control: prove the scan actually looked at files. A convention test that silently scanned
        // nothing is worse than no test, and a moved directory is exactly how that happens.
        Assert.True(directories.Sum(SourceScanner.FileCount) > 10, "the source scan found almost no files to read");

        Assert.True(
            hits.Count == 0,
            "Cloud-provider vocabulary found in connector code (ADR 0003 — bastion is configuration, "
            + $"not a branch on where the target lives):{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));
    }

    /// <summary>A comment line, including XML doc and the continuation lines of a block comment.</summary>
    private static bool IsComment(string line)
    {
        var trimmed = line.TrimStart();
        return trimmed.StartsWith("//", StringComparison.Ordinal)
               || trimmed.StartsWith("*", StringComparison.Ordinal)
               || trimmed.StartsWith("/*", StringComparison.Ordinal);
    }

    private static ServiceProvider BuildContainer()
    {
        var credentials = new FakeCredentialProvider();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ICredentialProvider>(credentials);
        services.AddConnectorsModule(new ConfigurationBuilder().Build());
        return services.BuildServiceProvider(validateScopes: true);
    }
}
