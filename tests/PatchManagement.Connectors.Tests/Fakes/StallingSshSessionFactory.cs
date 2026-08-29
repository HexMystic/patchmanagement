using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Ssh;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// A factory whose <see cref="ConnectAsync"/> blocks until the test releases it or the token fires —
/// the stand-in for a host that accepts a TCP connection and then goes quiet mid-handshake.
///
/// <para><b>Why a stalling FACTORY and not a stalling session.</b>
/// <see cref="SshConnector.TestConnectivityAsync"/> never runs a session operation: reaching an
/// authenticated session <em>is</em> the connectivity proof. So a probe under test spends all of its
/// time inside connect, and a fake that can only stall <c>RunAsync</c> cannot hold a probe open at
/// all. Stalling the connect is the only way to observe a probe in flight.</para>
///
/// <para><see cref="Entered"/> is the observable, for the same reason
/// <see cref="StallingSshSession.Entered"/> is: "the connect is now in flight" has to be an observed
/// fact rather than a slept-for hope, or the test measures the scheduler.</para>
/// </summary>
internal sealed class StallingSshSessionFactory : ISshSessionFactory
{
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Func<ISshSession> _session;

    public StallingSshSessionFactory(Func<ISshSession>? session = null) =>
        _session = session ?? (() => new RecordingSshSession());

    /// <summary>Completes once a connect has actually begun and is about to block.</summary>
    public Task Entered => _entered.Task;

    public int ConnectAttempts { get; private set; }

    /// <summary>Lets a stalled connect finish, for tests that need it to succeed rather than expire.</summary>
    public void Release() => _release.TrySetResult();

    public async Task<ISshSession> ConnectAsync(
        ConnectionPlan plan, CredentialResolver resolve, IHostKeyStore? hostKeys,
        TimeSpan connectTimeout, CancellationToken ct)
    {
        ConnectAttempts++;

        using (var credential = await resolve(plan.Destination.Credential, ct).ConfigureAwait(false))
        {
            // Resolved and disposed exactly as the real factory does, so credential-lifecycle
            // assertions stay meaningful for a test that uses this factory.
        }

        _entered.TrySetResult();

        // Completes on release, or throws on cancellation — what a real transport does when its
        // token fires mid-handshake.
        var cancelled = new TaskCompletionSource();
        await using var registration = ct.Register(() => cancelled.TrySetCanceled(ct));

        await await Task.WhenAny(_release.Task, cancelled.Task).ConfigureAwait(false);

        return _session();
    }
}
