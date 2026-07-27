using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests.Credentials;

/// <summary>
/// Exit criterion (b): credentials are resolved only through the Phase-1
/// <see cref="ICredentialProvider"/>, held in memory only, and released.
///
/// <para>These assert on the <em>buffers themselves</em> rather than on call counts.
/// <c>ResolvedCredential.Dispose</c> zeroes in place, so a buffer still holding non-zero bytes after
/// an operation returned is proof the consumer leaked it — and the paths that leak are never the
/// happy one. They are the auth failure and the cancellation, where an early return skips the
/// cleanup someone remembered to write only on the success path.</para>
/// </summary>
public sealed class CredentialLifecycleTests
{
    [Fact]
    public async Task Every_credential_resolved_on_a_successful_run_is_zeroed_afterwards()
    {
        var harness = ConnectorHarness.Build();

        await harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "uname -a" },
            CancellationToken.None);

        Assert.True(harness.Recorder.ResolveCount > 0, "sanity: the run resolved no credential at all");
        Assert.True(
            harness.Recorder.AllHandedOutBuffersAreZeroed,
            $"{harness.Recorder.UnzeroedBufferCount} resolved credential buffer(s) were left un-zeroed "
            + "after a successful run.");
    }

    [Fact]
    public async Task Every_credential_is_zeroed_when_authentication_fails()
    {
        var harness = ConnectorHarness.Build(
            connectThrows: new ConnectorConnectException(
                ConnectorOutcome.AuthFailed, "SSH authentication was rejected."));

        var result = await harness.Connector.TestConnectivityAsync(
            ConnectorHarness.Target(), CancellationToken.None);

        Assert.Equal(ConnectorOutcome.AuthFailed, result.Outcome);
        Assert.True(harness.Recorder.ResolveCount > 0, "sanity: nothing was resolved, so nothing was proven");
        Assert.True(
            harness.Recorder.AllHandedOutBuffersAreZeroed,
            $"{harness.Recorder.UnzeroedBufferCount} credential buffer(s) survived an auth failure. "
            + "The failure path skipped the cleanup the success path performs.");
    }

    [Fact]
    public async Task Every_credential_is_zeroed_when_the_caller_cancels_mid_operation()
    {
        var cts = new CancellationTokenSource();
        var harness = ConnectorHarness.Build(session: () =>
        {
            // Cancel at the moment the session is handed over: after the credential has been
            // resolved, before the command runs — the window where a leak would go unnoticed.
            cts.Cancel();
            return new RecordingSshSession();
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "sleep 30" },
            cts.Token));

        Assert.True(harness.Recorder.ResolveCount > 0, "sanity: nothing was resolved, so nothing was proven");
        Assert.True(
            harness.Recorder.AllHandedOutBuffersAreZeroed,
            $"{harness.Recorder.UnzeroedBufferCount} credential buffer(s) survived a cancellation.");
    }

    [Fact]
    public async Task The_connector_resolves_through_the_provider_rather_than_holding_material()
    {
        var harness = ConnectorHarness.Build();
        var target = ConnectorHarness.Target();

        await harness.Connector.RunAsync(target, new RemoteCommand { CommandLine = "true" }, CancellationToken.None);
        var afterFirst = harness.Recorder.CountFor(ConnectorHarness.LoginCredential);

        Assert.True(afterFirst > 0,
            "The connector never called ICredentialProvider — it is getting its material some other way.");
        Assert.All(harness.Recorder.Resolved, r => Assert.Equal(ConnectorHarness.LoginCredential.Id, r.Id));
    }

    [Fact]
    public async Task A_lease_is_released_even_when_the_connection_fails()
    {
        var harness = ConnectorHarness.Build(
            connectThrows: new ConnectorConnectException(ConnectorOutcome.Unreachable, "no route"));

        var result = await harness.Connector.TestConnectivityAsync(
            ConnectorHarness.Target(), CancellationToken.None);

        Assert.Equal(ConnectorOutcome.Unreachable, result.Outcome);

        // A lease leaked on the failure path is invisible until the budget is exhausted, at which
        // point the whole process stops connecting and the cause is hours of log-reading away.
        Assert.Equal(0, harness.Governor.ActiveGlobal);
        Assert.Equal(0, harness.Governor.ActiveForTenant(ConnectorHarness.Tenant));
    }
}
