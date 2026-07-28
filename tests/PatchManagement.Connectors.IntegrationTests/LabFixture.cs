using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// Brings up a connector wired to the real lab fleet.
///
/// <para><b>Missing infrastructure FAILS; it does not skip.</b> xunit 2.9.2 has no
/// <c>Assert.Skip</c>, the repo's PostgresFixture hard-fails the same way, and ROADMAP.md records
/// suite sizes as absolute counts that silent skips would quietly corrupt — a fleet that stopped
/// being exercised would look identical to one that passes. The failure message names the exact
/// command to fix it, in the style of HostModuleDiscoveryTests.</para>
/// </summary>
public sealed class LabFixture : IAsyncLifetime
{
    public static readonly CredentialRef LabCredential = new(Guid.Parse("1ab00000-0000-0000-0000-000000000001"));
    public static readonly Guid Tenant = Guid.Parse("7e9a0000-0000-0000-0000-000000000001");

    public FakeCredentialProvider Credentials { get; } = new();
    public SshConnector Connector { get; private set; } = null!;
    internal SemaphoreConnectionGovernor Governor { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        var keyPath = RepoPaths.LabPrivateKey();
        if (!File.Exists(keyPath))
        {
            throw new InvalidOperationException(
                $"The lab SSH key is missing at '{keyPath}'.{Environment.NewLine}"
                + "Generate it:   pwsh scripts/lab-keygen.ps1" + Environment.NewLine
                + "If this is a worktree, it should have been copied by .worktreeinclude — recreate "
                + "the worktree through the normal tooling rather than copying the key by hand.");
        }

        var unreachable = new List<string>();
        foreach (var host in LabFleet.All)
        {
            var failure = await ProbeAsync(host.Port).ConfigureAwait(false);
            if (failure is not null)
                unreachable.Add($"{host.Name} (127.0.0.1:{host.Port}) — {failure}");
        }

        if (unreachable.Count > 0)
        {
            throw new InvalidOperationException(
                $"The lab fleet is not reachable: {string.Join(", ", unreachable)}.{Environment.NewLine}"
                + "Bring it up FROM THE MAIN WORKTREE (WORKFLOW.md §3 — only it runs Docker infra):"
                + Environment.NewLine
                + "  docker compose -f lab/docker-compose.yml up -d" + Environment.NewLine
                + "Then confirm with: pwsh scripts/verify-env.ps1");
        }

        Credentials.AddLabKey(LabCredential, LabFleet.Username);

        var options = Options.Create(new ConnectorConcurrencyOptions
        {
            GlobalMaxConnections = 16,
            PerTenantMaxConnections = 16,
            PerHostMaxConnections = 8,
        });

        Governor = new SemaphoreConnectionGovernor(options);

        Connector = new SshConnector(
            Credentials,
            // The lab rebuilds its containers constantly and they regenerate host keys each time, so
            // there is nothing stable to pin. This opt-in is deliberate, explicit and scoped to the
            // lab; the product default REFUSES unknown host keys, and a real fleet needs the verified
            // -key store deferred to Phase 4 (D-301).
            new SshNetSessionFactory(new ConnectorSecurityOptions { AllowUnknownHostKeys = true }),
            new SshConnectionPool(options),
            Governor,
            new KeyedOperationCoordinator(),
            NullLogger<SshConnector>.Instance);
    }

    /// <summary>
    /// A connector backed by a different credential provider, for tests about authentication
    /// failure. Shares nothing with <see cref="Connector"/> so a rejected key cannot poison the
    /// pooled sessions the rest of the suite is using.
    /// </summary>
    public SshConnector ConnectorWith(ICredentialProvider credentials, TimeSpan? authenticationBudget = null)
    {
        var options = Options.Create(new ConnectorConcurrencyOptions());

        return new SshConnector(
            credentials,
            new SshNetSessionFactory(new ConnectorSecurityOptions { AllowUnknownHostKeys = true }),
            new SshConnectionPool(options),
            new SemaphoreConnectionGovernor(options),
            new KeyedOperationCoordinator(),
            NullLogger<SshConnector>.Instance,
            new ConnectorTimeoutOptions
            {
                // Reachability stays short — the point of the split. The AUTH budget is what a caller
                // varies when it wants to see how a slow rejection classifies.
                Reachability = TimeSpan.FromSeconds(5),
                Authentication = authenticationBudget ?? TimeSpan.FromSeconds(45),
            });
    }

    /// <summary>
    /// A real, authenticated <see cref="ISshSession"/> over SSH.NET — no fake anywhere in the path.
    ///
    /// <para>The connector's own fakes stop at this interface, which is exactly where the stdin defect
    /// lived: <c>RecordingSshSession</c> records a buffer and returns, so the transport's own rules
    /// about <em>when</em> an input stream may be created were never exercised by any test. Anything
    /// asserting how bytes actually reach a remote command has to start here.</para>
    /// </summary>
    internal async Task<ISshSession> OpenRealSessionAsync(LabHost host, CancellationToken ct)
    {
        var factory = new SshNetSessionFactory(new ConnectorSecurityOptions { AllowUnknownHostKeys = true });
        var plan = ConnectionPlanner.Plan(TargetFor(host));

        return await factory
            .ConnectAsync(plan, Credentials.ResolveAsync, TimeSpan.FromSeconds(30), ct)
            .ConfigureAwait(false);
    }

    public EndpointTarget TargetFor(LabHost host) => new()
    {
        TenantId = Tenant,
        Host = "localhost",
        Port = host.Port,
        Protocol = EndpointProtocol.Ssh,
        Credential = LabCredential,
        AssetId = host.Name,
    };

    /// <summary>
    /// Null when the port accepts a connection, otherwise why it did not.
    ///
    /// <para>The reason is carried out rather than swallowed. A probe that collapses every failure
    /// into "unreachable" tells an operator to restart a fleet that is already running, which is the
    /// same misleading-diagnosis trap the vault's lock code hit — and it wasted time here before this
    /// was fixed.</para>
    ///
    /// <para>127.0.0.1 explicitly, not "localhost": on Windows that name resolves to ::1 first, and a
    /// probe that happens to take the IPv6 path can fail against a publish that is answering happily
    /// on IPv4 — reporting a dead fleet that a plain ssh reaches without trouble.</para>
    /// </summary>
    private static async Task<string?> ProbeAsync(int port)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(IPAddress.Loopback, port, cts.Token).ConfigureAwait(false);
            return client.Connected ? null : "connect completed but the socket is not connected";
        }
        catch (OperationCanceledException)
        {
            return "timed out after 5s";
        }
        catch (Exception ex)
        {
            return $"{ex.GetType().Name}: {ex.Message}";
        }
    }

    public Task DisposeAsync()
    {
        Governor?.Dispose();
        return Task.CompletedTask;
    }
}

[CollectionDefinition(Name)]
public sealed class LabCollection : ICollectionFixture<LabFixture>
{
    public const string Name = "lab-fleet";
}
