using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Connectors;
using PatchManagement.Connectors.DependencyInjection;
using PatchManagement.Connectors.Facts;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests.Facts;

/// <summary>
/// Proves <see cref="EndpointFactsCollector"/> reaches an endpoint over the protocol the TARGET
/// names, when resolved <b>from the container</b> rather than hand-built.
///
/// <para><b>The defect this exists to stop.</b> The collector took a single
/// <see cref="IEndpointConnector"/>, and the module registers two — SSH and WinRM. .NET's DI hands a
/// single-service request the LAST registration, so every container-resolved collector spoke WinRM,
/// whatever the target said. Every SSH inventory through it came back <c>AuthFailed</c>, and WinRM
/// facts are deferred anyway (D-302, <c>Unsupported</c> by design), so the resolved object could
/// never have worked at all.</para>
///
/// <para><b>Why it survived.</b> Not because a test built it by hand — because <b>nothing
/// constructed or exercised it anywhere</b>. It shipped with no coverage of any kind, and Phase 4's
/// inventory slice was the first code to resolve it. A type that is only ever registered is not
/// tested by its registration.</para>
///
/// <para><b>Resolved through the real <c>AddConnectorsModule</c>, deliberately.</b> A test that
/// constructed the collector itself would be asserting against its own wiring and would have gone on
/// passing throughout — which is exactly the hole being closed. The registry spy is registered
/// BEFORE the module so the module's <c>TryAdd</c> leaves it in place: the container is otherwise
/// the shipped one.</para>
/// </summary>
public sealed class FactsCollectorResolutionTests
{
    private static readonly CredentialRef Credential = new(Guid.Parse("5eed0000-0000-0000-0000-000000000001"));

    [Fact]
    public async Task A_container_resolved_collector_dispatches_on_the_targets_protocol()
    {
        var linux = new ScriptedLinuxConnector(EndpointProtocol.Ssh);
        var registry = new SpyRegistry(linux);

        await using var provider = BuildContainer(registry);
        await using var scope = provider.CreateAsyncScope();

        var collector = scope.ServiceProvider.GetRequiredService<EndpointFactsCollector>();

        var facts = await collector.CollectAsync(SshTarget(), CancellationToken.None);

        Assert.Equal([EndpointProtocol.Ssh], registry.Requested);
        Assert.Equal("ubuntu", facts.OsId);
        Assert.Equal("22.04", facts.OsVersion);
        Assert.Equal("dpkg", facts.PackageManager);
        Assert.Equal("bash", Assert.Single(facts.Packages).Name);
    }

    /// <summary>
    /// The registry must be CONSULTED, not merely present. A collector that captured one connector
    /// at construction would satisfy the test above whenever the captured one happened to be right,
    /// so the spy's own record is what carries the proof.
    /// </summary>
    [Fact]
    public async Task The_collector_asks_the_registry_rather_than_capturing_one_connector()
    {
        var linux = new ScriptedLinuxConnector(EndpointProtocol.Ssh);
        var registry = new SpyRegistry(linux);

        await using var provider = BuildContainer(registry);
        await using var scope = provider.CreateAsyncScope();

        var collector = scope.ServiceProvider.GetRequiredService<EndpointFactsCollector>();

        Assert.Empty(registry.Requested);

        await collector.CollectAsync(SshTarget(), CancellationToken.None);

        Assert.NotEmpty(registry.Requested);
        Assert.All(registry.Requested, p => Assert.Equal(EndpointProtocol.Ssh, p));
    }

    private static ServiceProvider BuildContainer(IEndpointConnectorRegistry registry)
    {
        var credentials = new FakeCredentialProvider();
        credentials.Add(Credential, "key"u8.ToArray(), CredentialKind.SshKey, "labadmin");

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ICredentialProvider>(credentials);

        // BEFORE the module: AddConnectorsModule uses TryAdd, so this stays in place and the rest of
        // the container is the shipped composition.
        services.AddScoped(_ => registry);

        services.AddConnectorsModule(new ConfigurationBuilder().Build());

        return services.BuildServiceProvider(validateScopes: true);
    }

    private static EndpointTarget SshTarget() => new()
    {
        TenantId = Guid.Parse("7e9a0000-0000-0000-0000-000000000001"),
        // Loopback only (NEVER #4). Nothing is contacted regardless — the scripted connector answers.
        Host = "127.0.0.1",
        Port = 2201,
        Protocol = EndpointProtocol.Ssh,
        Credential = Credential,
    };

    /// <summary>Records every protocol the collector asked for, and hands back one connector.</summary>
    private sealed class SpyRegistry(IEndpointConnector connector) : IEndpointConnectorRegistry
    {
        public List<EndpointProtocol> Requested { get; } = [];

        public IEndpointConnector For(EndpointProtocol protocol)
        {
            Requested.Add(protocol);
            return connector;
        }

        public IEndpointConnector For(EndpointTarget target) => For(target.Protocol);
    }

    /// <summary>Answers the four commands the collector issues on a dpkg host. Opens no socket.</summary>
    private sealed class ScriptedLinuxConnector(EndpointProtocol protocol) : IEndpointConnector
    {
        public EndpointProtocol Protocol => protocol;

        public Task<ConnectivityResult> TestConnectivityAsync(EndpointTarget target, CancellationToken ct) =>
            Task.FromResult(ConnectivityResult.Reachable(TimeSpan.Zero));

        public Task<CommandResult> RunAsync(EndpointTarget target, RemoteCommand command, CancellationToken ct)
        {
            var line = command.CommandLine;

            var stdout = line switch
            {
                _ when line.Contains("os-release", StringComparison.Ordinal) => "ubuntu|22.04\n",
                _ when line.Contains("uname -m", StringComparison.Ordinal) => "x86_64\n",
                _ when line.Contains("command -v dpkg-query", StringComparison.Ordinal) => "/usr/bin/dpkg-query\n",
                _ when line.Contains("dpkg-query -W", StringComparison.Ordinal) => "bash\t5.1-2\tamd64\n",
                _ => string.Empty,
            };

            return Task.FromResult(CommandResult.Ran(0, stdout, string.Empty, TimeSpan.Zero));
        }

        public Task<FileResult> PushAsync(EndpointTarget target, FileTransfer file, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<FileResult> PullAsync(EndpointTarget target, FileTransfer file, CancellationToken ct) =>
            throw new NotSupportedException();
    }
}
