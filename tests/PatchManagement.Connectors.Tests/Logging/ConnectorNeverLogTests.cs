using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Connectors.WinRm;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;
using PatchManagement.TestSupport.Logging;

namespace PatchManagement.Connectors.Tests.Logging;

/// <summary>
/// CLAUDE.md NEVER #1 for the connector: a resolved credential is used in memory only and never
/// reaches a logger, on any channel.
///
/// <para>Each sweep covers UTF-8, base64 and both hex casings, and BOTH the formatted message and
/// the structured state. The structured channel is the one that matters most: the redaction belt
/// does not scrub it (ADR 0012 decision D), it is what JSON and OTel sinks actually serialize, and a
/// <c>byte[]</c> renders there as base64 rather than the "System.Byte[]" that <c>string.Format</c>
/// would hide it behind.</para>
/// </summary>
public sealed class ConnectorNeverLogTests
{
    /// <summary>
    /// The live-sink control, and the reason every other test in this file means anything.
    ///
    /// <para>A sweep that finds no secret proves the connector did not log one only if the sink
    /// could have caught it. A misconfigured harness — wrong logger, filtered level, discarded state
    /// — produces a perfectly clean sweep over an empty buffer and reads exactly like success. So:
    /// the SAME sink, handed the SAME sentinel through an ordinary logger, must record it on both
    /// channels.</para>
    /// </summary>
    [Fact]
    public void The_sink_does_record_a_secret_when_one_is_actually_logged()
    {
        var sink = new CapturingLoggerProvider();
        var sentinel = "SENTINEL-" + Guid.NewGuid().ToString("N");

        var logger = sink.CreateLogger("Some.Unrelated.Component");
        logger.LogInformation("leaking {Secret} deliberately", sentinel);

        Assert.True(SecretSweep.Scan(sentinel, sink.AllFormatted).Leaked, "the formatted channel is dead");
        Assert.True(SecretSweep.Scan(sentinel, sink.AllRenderedValues).Leaked, "the structured channel is dead");
    }

    [Fact]
    public async Task A_successful_run_puts_no_key_material_on_any_log_channel()
    {
        var sink = new CapturingLoggerProvider();
        var credentials = new FakeCredentialProvider();
        var sentinel = credentials.AddSentinel(ConnectorHarness.LoginCredential);

        var connector = Build(credentials, sink);

        var result = await connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "id -u" },
            CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);
        AssertClean(sentinel, sink);
    }

    [Fact]
    public async Task A_failed_connectivity_probe_puts_no_key_material_on_any_log_channel()
    {
        // The path that DOES log. The connector's only log statements are on probe failure, so this
        // is where a careless "{Target}" or a logged exception would surface a secret.
        var sink = new CapturingLoggerProvider();
        var credentials = new FakeCredentialProvider();
        var sentinel = credentials.AddSentinel(ConnectorHarness.LoginCredential);

        var connector = Build(
            credentials, sink,
            new StubSshSessionFactory(new ConnectorConnectException(
                ConnectorOutcome.AuthFailed, "SSH authentication was rejected.")));

        var result = await connector.TestConnectivityAsync(ConnectorHarness.Target(), CancellationToken.None);

        Assert.Equal(ConnectorOutcome.AuthFailed, result.Outcome);
        Assert.NotEqual(string.Empty, sink.AllFormatted); // sanity: it did log something
        AssertClean(sentinel, sink);

        // The failure detail is returned to the caller too, so sweep that as well — it is the
        // likeliest thing for a caller to log.
        Assert.False(SecretSweep.Scan(sentinel, result.Detail ?? string.Empty).Leaked);
    }

    [Fact]
    public async Task A_thrown_exception_carries_no_key_material()
    {
        var sink = new CapturingLoggerProvider();
        var credentials = new FakeCredentialProvider();
        var sentinel = credentials.AddSentinel(ConnectorHarness.LoginCredential);

        var connector = Build(credentials, sink);

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var ex = await Record.ExceptionAsync(() => connector.RunAsync(
            ConnectorHarness.Target(), new RemoteCommand { CommandLine = "id -u" }, cts.Token));

        // Exceptions escaping the connector are logged by ASP.NET OUTSIDE any redaction scope —
        // the residual ROADMAP hands Phase 3 explicitly. Sweep the whole exception, not just its
        // message: an inner exception or Data entry counts.
        Assert.False(SecretSweep.Scan(sentinel, ex?.ToString() ?? string.Empty).Leaked);
        AssertClean(sentinel, sink);
    }

    [Fact]
    public async Task An_elevated_command_puts_no_sudo_password_on_any_log_channel()
    {
        var sink = new CapturingLoggerProvider();
        var credentials = new FakeCredentialProvider();
        credentials.Add(ConnectorHarness.LoginCredential, "key"u8.ToArray(), CredentialKind.SshKey, "labadmin");
        var sudoSentinel = credentials.AddSentinel(
            ConnectorHarness.SudoCredential, CredentialKind.WindowsPassword, "labadmin");

        var connector = Build(credentials, sink);

        await connector.RunAsync(
            ConnectorHarness.Target(withSudo: true),
            new RemoteCommand { CommandLine = "dnf -y upgrade", RequiresElevation = true },
            CancellationToken.None);

        AssertClean(sudoSentinel, sink);
    }

    // ---------------------------------------------------------------------------------------
    // The WinRM connector.
    //
    // Cold review R2 finding #4: every fact above builds an SshConnector over a StubSshSessionFactory,
    // so WinRmConnector and HttpWinRmClient had NO never-log coverage whatsoever — a secret logged
    // from either passed the whole suite green, which the reviewer demonstrated by planting one. The
    // module-wide source scan in ConnectorLoggingConventionTests is the other half of that fix; these
    // are the behavioural half.
    //
    // A scripted handler stands in for the Windows host (NEVER #4 forbids a real one from a dev
    // session), which is enough: the secret reaches the client here exactly as it would in production
    // — the handler factory receives the live ResolvedCredential.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_successful_winrm_command_puts_no_password_on_any_log_channel()
    {
        var sink = new CapturingLoggerProvider();
        var credentials = new FakeCredentialProvider();
        var sentinel = credentials.AddSentinel(
            ConnectorHarness.LoginCredential, CredentialKind.WindowsPassword, "Administrator");

        var handler = WinRmScript.Succeeding();
        var connector = BuildWinRm(credentials, sink, handler);

        var result = await connector.RunAsync(
            WinRmTarget(), new RemoteCommand { CommandLine = "whoami" }, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Ok, result.Outcome);

        // Liveness control. A sweep over a code path that never ran is indistinguishable from a clean
        // one, and that is precisely the defect this test exists to close: the WinRM connector was
        // never exercised with a sink at all, so a planted secret passed the suite green. Traffic on
        // the wire proves the credential really reached the transport.
        Assert.NotEmpty(handler.Requests);
        Assert.Contains(handler.Requests, r => r.Contains("Shell", StringComparison.OrdinalIgnoreCase));

        AssertClean(sentinel, sink);
    }

    [Fact]
    public async Task A_rejected_winrm_credential_puts_no_password_on_any_log_channel()
    {
        // The WinRM path that DOES log: the probe's failure branch.
        var sink = new CapturingLoggerProvider();
        var credentials = new FakeCredentialProvider();
        var sentinel = credentials.AddSentinel(
            ConnectorHarness.LoginCredential, CredentialKind.WindowsPassword, "Administrator");

        var connector = BuildWinRm(credentials, sink, WinRmScript.RejectingCredentials());

        var result = await connector.TestConnectivityAsync(WinRmTarget(), CancellationToken.None);

        Assert.Equal(ConnectorOutcome.AuthFailed, result.Outcome);
        Assert.NotEqual(string.Empty, sink.AllFormatted); // sanity: it did log something
        AssertClean(sentinel, sink);
        Assert.False(SecretSweep.Scan(sentinel, result.Detail ?? string.Empty).Leaked);
    }

    [Fact]
    public async Task A_winrm_transfer_puts_no_password_on_any_log_channel()
    {
        var sink = new CapturingLoggerProvider();
        var credentials = new FakeCredentialProvider();
        var sentinel = credentials.AddSentinel(
            ConnectorHarness.LoginCredential, CredentialKind.WindowsPassword, "Administrator");

        var connector = BuildWinRm(credentials, sink, WinRmScript.Succeeding());

        await connector.PushAsync(
            WinRmTarget(),
            new FileTransfer { RemotePath = @"C:\temp\payload.bin", Content = "payload"u8.ToArray() },
            CancellationToken.None);

        AssertClean(sentinel, sink);
    }

    // ---------------------------------------------------------------------------------------
    // The REAL SSH session factory.
    //
    // Same finding: the factory that actually handles key material was never in the path of a
    // never-log assertion — every fact above stops at StubSshSessionFactory. Pointing it at a closed
    // port drives its real reachability and error-mapping code with real key material and a sink
    // attached, with no lab dependency. The lab suite carries the authenticated half
    // (SshFleetNeverLogTests), where the key is the fleet's genuine one.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_unreachable_host_through_the_REAL_session_factory_logs_no_key_material()
    {
        var sink = new CapturingLoggerProvider();
        var credentials = new FakeCredentialProvider();
        var sentinel = credentials.AddSentinel(ConnectorHarness.LoginCredential);

        var options = Options.Create(new ConnectorConcurrencyOptions());
        var connector = new SshConnector(
            credentials,
            // The real thing — not a stub. This is the type that reads, parses and hands key bytes to
            // SSH.NET, so it is where a careless diagnostic would surface one.
            new SshNetSessionFactory(
                new ConnectorSecurityOptions(),
                new ConnectorTimeoutOptions { Reachability = TimeSpan.FromSeconds(2) }),
            new SshConnectionPool(options),
            new SemaphoreConnectionGovernor(options),
            new KeyedOperationCoordinator(),
            sink.CreateLogger<SshConnector>());

        // 127.0.0.1:1 — nothing listens there, and it is unambiguously local (NEVER #4).
        var target = ConnectorHarness.Target() with { Host = "127.0.0.1", Port = 1 };

        var result = await connector.TestConnectivityAsync(target, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Unreachable, result.Outcome);
        Assert.NotEqual(string.Empty, sink.AllFormatted); // sanity: the failure branch did log
        AssertClean(sentinel, sink);
        Assert.False(SecretSweep.Scan(sentinel, result.Detail ?? string.Empty).Leaked);
    }

    private static EndpointTarget WinRmTarget() => new()
    {
        TenantId = ConnectorHarness.Tenant,
        Host = "localhost",
        Port = 5986,
        Protocol = EndpointProtocol.WinRm,
        Credential = ConnectorHarness.LoginCredential,
        AssetId = "lab-winrm-scripted",
    };

    private static WinRmConnector BuildWinRm(
        FakeCredentialProvider credentials, CapturingLoggerProvider sink, ScriptedHttpHandler handler)
    {
        var options = Options.Create(new ConnectorConcurrencyOptions());

        return new WinRmConnector(
            credentials,
            new HttpWinRmClient(_ => handler),
            new SemaphoreConnectionGovernor(options),
            new KeyedOperationCoordinator(),
            sink.CreateLogger<WinRmConnector>());
    }

    private static void AssertClean(byte[] sentinel, CapturingLoggerProvider sink)
    {
        var formatted = SecretSweep.Scan(sentinel, sink.AllFormatted);
        Assert.False(formatted.Leaked, $"formatted channel: {formatted.Describe()}");

        var structured = SecretSweep.Scan(sentinel, sink.AllRenderedValues);
        Assert.False(structured.Leaked, $"structured channel: {structured.Describe()}");

        var exceptions = SecretSweep.Scan(sentinel, sink.AllExceptionText);
        Assert.False(exceptions.Leaked, $"exception channel: {exceptions.Describe()}");
    }

    private static SshConnector Build(
        FakeCredentialProvider credentials, CapturingLoggerProvider sink, StubSshSessionFactory? factory = null)
    {
        var options = Options.Create(new ConnectorConcurrencyOptions());

        return new SshConnector(
            credentials,
            factory ?? new StubSshSessionFactory(() => new RecordingSshSession()),
            new SshConnectionPool(options),
            new SemaphoreConnectionGovernor(options),
            new KeyedOperationCoordinator(),
            sink.CreateLogger<SshConnector>());
    }
}
