using PatchManagement.Connectors.Facts;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;
using PatchManagement.TestSupport.Logging;

namespace PatchManagement.Connectors.Tests.Logging;

/// <summary>
/// The connector's most realistic leak, and it is not a logger call at all.
///
/// <para>Remote stderr flowed into <c>ConnectorConnectException.Message</c>, which surfaces as
/// <c>FileResult.Detail</c>, which a caller logs. The module has no control over that caller, so the
/// containment has to happen where the diagnostic is built. Endpoint output is arbitrary text chosen
/// by the endpoint — it routinely quotes back the command that failed, and a command line is the
/// likeliest place for a caller-embedded secret.</para>
///
/// <para>The distinction being drawn here is deliberate and narrow: <b>returning</b> remote output is
/// correct — it is the caller's payload and lives on <c>CommandResult.StandardError</c> — while
/// <b>describing a failure with it</b> is not.</para>
/// </summary>
public sealed class RemoteOutputContainmentTests
{
    private const string Sentinel = "STDERR-SENTINEL-9f2a";

    [Fact]
    public async Task Remote_stderr_is_returned_to_the_caller_as_payload()
    {
        // The control for everything below. If stderr were simply dropped, the containment tests
        // would pass trivially and the connector would be useless for diagnosing a failing command.
        var session = new RecordingSshSession(_ =>
            CommandResult.Ran(1, string.Empty, Sentinel, TimeSpan.Zero));

        var harness = ConnectorHarness.Build(session: () => session);

        var result = await harness.Connector.RunAsync(
            ConnectorHarness.Target(), new RemoteCommand { CommandLine = "false" }, CancellationToken.None);

        Assert.Contains(Sentinel, result.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Remote_stderr_does_not_reach_the_failure_detail_a_caller_logs()
    {
        var session = new RecordingSshSession(_ =>
            CommandResult.Ran(1, string.Empty, Sentinel, TimeSpan.Zero));

        var harness = ConnectorHarness.Build(session: () => session);

        var result = await harness.Connector.RunAsync(
            ConnectorHarness.Target(), new RemoteCommand { CommandLine = "false" }, CancellationToken.None);

        Assert.False(
            SecretSweep.Scan(Sentinel, result.Detail ?? string.Empty).Leaked,
            "Result.Detail carries remote output; a caller logging it publishes endpoint-chosen text.");
    }

    [Fact]
    public void A_connect_failure_message_is_a_bounded_reason_code()
    {
        var ex = new ConnectorConnectException(ConnectorOutcome.ProtocolError, ConnectorReason.WinRmUploadFailed);

        // Greppable, stable, and incapable of carrying anything the endpoint chose.
        Assert.Equal("winrm-upload-failed", ex.Message);
        Assert.DoesNotContain(" ", ex.Message.Trim(), StringComparison.Ordinal);
    }

    [Fact]
    public void Facts_failures_describe_themselves_without_the_command_text()
    {
        var ex = new FactsCollectionException($"{ConnectorReason.FactsCommandFailed} ({ConnectorOutcome.Unreachable})");

        // The command line used to be interpolated here. It is the single likeliest carrier of a
        // caller-embedded secret, and this exception is thrown rather than returned — so it lands in
        // ASP.NET's logger, outside any redaction scope (ADR 0012's residual for Phase 3).
        Assert.Contains("facts-command-failed", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("curl", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("cat /etc/os-release", ex.Message, StringComparison.Ordinal);
    }
}
