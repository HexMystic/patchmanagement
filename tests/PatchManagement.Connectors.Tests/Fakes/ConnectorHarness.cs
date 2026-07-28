using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// Builds an <see cref="SshConnector"/> over fakes: real governor, real pool, real coordinator, but
/// a stub session factory. Keeping the concurrency pieces REAL matters — they are what the connector
/// leases against, and substituting them would hide lease leaks, which are among the failures these
/// tests exist to catch.
/// </summary>
internal sealed class ConnectorHarness
{
    public static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly CredentialRef LoginCredential = new(Guid.Parse("22222222-2222-2222-2222-222222222222"));
    public static readonly CredentialRef SudoCredential = new(Guid.Parse("33333333-3333-3333-3333-333333333333"));

    public required FakeCredentialProvider Credentials { get; init; }
    public required RecordingCredentialProvider Recorder { get; init; }
    public required SemaphoreConnectionGovernor Governor { get; init; }
    public required SshConnector Connector { get; init; }

    private StubSshSessionFactory? Stub { get; init; }

    /// <summary>
    /// The stub factory the harness built. Throws rather than returning null when the caller supplied
    /// its own factory, so a test asserting on <c>ConnectAttempts</c> against a harness that has no
    /// stub fails by saying so instead of by NullReferenceException three frames away.
    /// </summary>
    public StubSshSessionFactory SessionFactory =>
        Stub ?? throw new InvalidOperationException(
            "This harness was built with a custom ISshSessionFactory, so there is no stub to inspect.");

    public static ConnectorHarness Build(
        Func<ISshSession>? session = null,
        Exception? connectThrows = null,
        ISshSessionFactory? sessionFactory = null,
        Action<FakeCredentialProvider>? configureCredentials = null,
        Action<ConnectorConcurrencyOptions>? configureConcurrency = null,
        TimeProvider? timeProvider = null,
        ConnectorTimeoutOptions? timeouts = null)
    {
        var credentials = new FakeCredentialProvider();
        credentials.Add(LoginCredential, "fake-ed25519-private-key"u8.ToArray(), CredentialKind.SshKey, "labadmin");
        configureCredentials?.Invoke(credentials);

        var recorder = new RecordingCredentialProvider(credentials);

        var options = new ConnectorConcurrencyOptions();
        configureConcurrency?.Invoke(options);
        var wrapped = Options.Create(options);

        var governor = new SemaphoreConnectionGovernor(wrapped);

        StubSshSessionFactory? stub = null;
        if (sessionFactory is null)
        {
            stub = connectThrows is not null
                ? new StubSshSessionFactory(connectThrows)
                : new StubSshSessionFactory(session ?? (() => new RecordingSshSession()));
        }

        var factory = sessionFactory ?? stub!;

        var connector = new SshConnector(
            recorder,
            factory,
            new SshConnectionPool(wrapped, timeProvider),
            governor,
            new KeyedOperationCoordinator(),
            NullLogger<SshConnector>.Instance,
            timeouts,
            timeProvider);

        return new ConnectorHarness
        {
            Credentials = credentials,
            Recorder = recorder,
            Governor = governor,
            Connector = connector,
            Stub = stub,
        };
    }

    /// <summary>A lab-shaped target. <paramref name="withSudo"/> attaches a privilege credential.</summary>
    public static EndpointTarget Target(bool withSudo = false) => new()
    {
        TenantId = Tenant,
        Host = "localhost",
        Port = 2201,
        Protocol = EndpointProtocol.Ssh,
        Credential = LoginCredential,
        PrivilegeCredential = withSudo ? SudoCredential : null,
        AssetId = "lab-ubuntu2204",
    };
}
