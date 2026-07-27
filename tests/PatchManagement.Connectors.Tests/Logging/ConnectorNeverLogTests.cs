using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
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
