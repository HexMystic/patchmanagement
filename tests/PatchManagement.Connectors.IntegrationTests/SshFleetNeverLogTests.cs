using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport;
using PatchManagement.TestSupport.Credentials;
using PatchManagement.TestSupport.Logging;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// NEVER #1 over the REAL transport, with the fleet's REAL private key.
///
/// <para>Cold review R2 finding #4: every never-log assertion in the unit suite ran against
/// <c>StubSshSessionFactory</c>, so <c>SshNetSessionFactory</c> — the type that actually reads,
/// parses and hands key bytes to SSH.NET — was never in the path of one. The unit suite now covers
/// its unreachable/error path; this covers the authenticated one, which is the only place the key is
/// genuinely used.</para>
///
/// <para>The sentinel here is not a synthetic value: it is <b>the fleet's actual private key
/// material</b>, read from disk and swept for in every encoding a sink might render it in. A
/// substitute would prove less, because a substitute is not what the code handles.</para>
/// </summary>
[Collection(LabCollection.Name)]
public sealed class SshFleetNeverLogTests(LabFixture lab)
{
    private static LabHost Host => LabFleet.All[0];

    private static byte[] LabKeyMaterial() => File.ReadAllBytes(RepoPaths.LabPrivateKey());

    /// <summary>
    /// Exercises connect, authenticate, run, push and pull against a live host, then sweeps every log
    /// channel for the private key.
    /// </summary>
    [Fact]
    public async Task A_full_real_session_puts_no_private_key_on_any_log_channel()
    {
        var sink = new CapturingLoggerProvider();
        var connector = BuildWithSink(sink);
        var target = lab.TargetFor(Host);
        var ct = CancellationToken.None;
        var remotePath = $"/tmp/pm-neverlog-{Guid.NewGuid():N}.bin";

        try
        {
            Assert.Equal(ConnectorOutcome.Ok, (await connector.TestConnectivityAsync(target, ct)).Outcome);
            Assert.Equal(ConnectorOutcome.Ok,
                (await connector.RunAsync(target, new RemoteCommand { CommandLine = "id -u" }, ct)).Outcome);
            Assert.Equal(ConnectorOutcome.Ok,
                (await connector.PushAsync(
                    target, new FileTransfer { RemotePath = remotePath, Content = "payload"u8.ToArray() }, ct)).Outcome);
            Assert.Equal(ConnectorOutcome.Ok,
                (await connector.PullAsync(target, new FileTransfer { RemotePath = remotePath }, ct)).Outcome);
        }
        finally
        {
            await connector.RunAsync(target, new RemoteCommand { CommandLine = $"rm -f {remotePath}" }, ct);
        }

        AssertKeyAbsent(sink);
    }

    /// <summary>
    /// The failure path, which is where diagnostics get written and therefore where a leak actually
    /// tends to appear. A key the fleet has never seen is rejected by real sshd.
    /// </summary>
    [Fact]
    public async Task A_real_authentication_failure_puts_no_private_key_on_any_log_channel()
    {
        var sink = new CapturingLoggerProvider();
        using var stray = new SshKeyScratch();

        var credentials = new FakeCredentialProvider();
        var strayRef = new CredentialRef(Guid.NewGuid());
        credentials.Add(strayRef, stray.PrivateKeyBytes, CredentialKind.SshKey, LabFleet.Username);

        var connector = BuildWithSink(sink, credentials);
        var target = lab.TargetFor(Host) with { Credential = strayRef };

        var result = await connector.TestConnectivityAsync(target, CancellationToken.None);

        Assert.Equal(ConnectorOutcome.AuthFailed, result.Outcome);
        Assert.NotEqual(string.Empty, sink.AllFormatted); // sanity: the failure branch logged

        // The REJECTED key is the secret at risk here — it is the one this code just handled.
        var sweep = SecretSweep.Scan(stray.PrivateKeyBytes, sink.Everything);
        Assert.False(sweep.Leaked, $"the rejected private key reached a log channel: {sweep.Describe()}");
        Assert.False(SecretSweep.Scan(stray.PrivateKeyBytes, result.Detail ?? string.Empty).Leaked);
    }

    /// <summary>
    /// The live-sink control, against the real connector's own category.
    ///
    /// <para>Both sweeps above prove a negative, and a negative over a dead sink is free. This hands
    /// the SAME sink, through the SAME logger category the connector is constructed with, the SAME
    /// key material — and requires it to be found. If this fails, the assertions above mean nothing.</para>
    /// </summary>
    [Fact]
    public void The_sink_does_find_the_lab_key_when_it_is_actually_logged()
    {
        var sink = new CapturingLoggerProvider();

        sink.CreateLogger<SshConnector>().LogInformation("leaking {Key} deliberately", LabKeyMaterial());

        var sweep = SecretSweep.Scan(LabKeyMaterial(), sink.Everything);
        Assert.True(sweep.Leaked, "the sink or the sweep is dead — every never-log assertion here is vacuous");
    }

    private void AssertKeyAbsent(CapturingLoggerProvider sink)
    {
        var key = LabKeyMaterial();

        foreach (var (channel, body) in new[]
                 {
                     ("formatted", sink.AllFormatted),
                     ("structured", sink.AllRenderedValues),
                     ("exception", sink.AllExceptionText),
                 })
        {
            var sweep = SecretSweep.Scan(key, body);
            Assert.False(sweep.Leaked, $"{channel} channel: {sweep.Describe()}");
        }
    }

    private SshConnector BuildWithSink(CapturingLoggerProvider sink, ICredentialProvider? credentials = null)
    {
        var options = Options.Create(new ConnectorConcurrencyOptions());

        return new SshConnector(
            credentials ?? lab.Credentials,
            new SshNetSessionFactory(new ConnectorSecurityOptions { AllowUnknownHostKeys = true }),
            new SshConnectionPool(options),
            new SemaphoreConnectionGovernor(options),
            new KeyedOperationCoordinator(),
            sink.CreateLogger<SshConnector>());
    }
}
