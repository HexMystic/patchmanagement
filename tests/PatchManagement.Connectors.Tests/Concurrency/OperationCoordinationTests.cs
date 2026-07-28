using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PatchManagement.Connectors.Concurrency;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests.Concurrency;

/// <summary>
/// The idempotency guard, and whose operations it is allowed to hold up.
///
/// <para><b>Cold review R2 finding #6.</b> The coordinator is a process-wide singleton and was keyed
/// on the caller-supplied <see cref="RemoteCommand.IdempotencyKey"/> verbatim — one line before the
/// governor call that carefully passes <c>target.TenantId</c>. Keys are predictable and derived from
/// things tenants share the shape of (<c>SshFleetTests</c> itself uses <c>"push:" + remotePath</c>,
/// e.g. <c>push:/tmp/patch.msu</c>), so one tenant holding such a key stalled every other tenant using
/// it. That is the exact defect the author found and fixed in <see cref="Connection.ConnectionKey"/>,
/// documenting there that isolation resting on incidental properties of the data is not isolation —
/// left unfixed one line away in the same method.</para>
/// </summary>
public sealed class OperationCoordinationTests
{
    private static readonly Guid TenantB = Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");

    private const string SharedKey = "push:/tmp/patch.msu";

    /// <summary>
    /// A tenant's in-flight operation must not hold up a DIFFERENT tenant using the same key.
    ///
    /// <para>The bound on the wait is load-bearing: unfixed, the second operation never starts at all,
    /// so an unbounded wait would hang the suite instead of failing it.</para>
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task One_tenants_idempotency_key_does_not_stall_another_tenant()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var factory = new ControllableSshSessionFactory(() => new StallingSshSession(gate));
        var connector = Build(factory);

        var first = connector.RunAsync(
            ConnectorHarness.Target(), Command(SharedKey), CancellationToken.None);

        await factory.OperationsReach(1).WaitAsync(TimeSpan.FromSeconds(10));

        // A different tenant, the SAME key. Nothing about tenant A's work is a reason to hold this up.
        var second = connector.RunAsync(
            ConnectorHarness.Target() with { TenantId = TenantB }, Command(SharedKey), CancellationToken.None);

        var reached = factory.OperationsReach(2);
        var settled = await Task.WhenAny(reached, Task.Delay(TimeSpan.FromSeconds(5)));

        Assert.True(
            settled == reached,
            "A second tenant's operation never started while another tenant held the same idempotency "
            + "key. The coordinator is a process-wide singleton keyed on the caller's raw key, so one "
            + "tenant can stall another's deployments — and the keys are predictable.");

        gate.SetResult();
        await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));
    }

    /// <summary>
    /// The control, and it is the whole reason the fix cannot simply drop the key: within ONE tenant
    /// the guard must still hold. A retry arriving while the original runs is serialised behind it
    /// rather than double-applied (HARD-PROBLEMS #6) — that is what the coordinator is for.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task The_same_tenant_reusing_a_key_is_still_serialised()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var factory = new ControllableSshSessionFactory(() => new StallingSshSession(gate));
        var connector = Build(factory);

        var first = connector.RunAsync(
            ConnectorHarness.Target(), Command(SharedKey), CancellationToken.None);

        await factory.OperationsReach(1).WaitAsync(TimeSpan.FromSeconds(10));

        // Same tenant, same key: the retry case.
        var retry = connector.RunAsync(
            ConnectorHarness.Target(), Command(SharedKey), CancellationToken.None);

        // Proving a negative, so this waits a real interval and requires that nothing happened. Held
        // in a local — OperationsReach hands back a fresh task per call, and comparing against a
        // second call would compare two different objects and always "pass".
        var reachedTwo = factory.OperationsReach(2);
        var settled = await Task.WhenAny(reachedTwo, Task.Delay(TimeSpan.FromSeconds(2)));

        Assert.True(
            settled != reachedTwo,
            "A retry with the same idempotency key ran concurrently with the original for the same "
            + "tenant, so the idempotency guard is gone.");
        Assert.Equal(1, factory.OperationsStarted);

        gate.SetResult();
        await Task.WhenAll(first, retry).WaitAsync(TimeSpan.FromSeconds(10));

        // ...and it did eventually run, rather than being dropped.
        Assert.Equal(2, factory.OperationsStarted);
    }

    /// <summary>
    /// Different keys within one tenant are independent — the guard is per-operation, not a global
    /// throttle. Without this, "serialise everything" would satisfy the test above.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Different_keys_for_one_tenant_run_concurrently()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var factory = new ControllableSshSessionFactory(() => new StallingSshSession(gate));
        var connector = Build(factory);

        var first = connector.RunAsync(
            ConnectorHarness.Target(), Command("push:/tmp/a.msu"), CancellationToken.None);
        var second = connector.RunAsync(
            ConnectorHarness.Target(), Command("push:/tmp/b.msu"), CancellationToken.None);

        await factory.OperationsReach(2).WaitAsync(TimeSpan.FromSeconds(10));

        gate.SetResult();
        await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static RemoteCommand Command(string idempotencyKey) => new()
    {
        CommandLine = "dnf -y upgrade",
        IdempotencyKey = idempotencyKey,
        Timeout = TimeSpan.FromMinutes(5),
    };

    private static SshConnector Build(ControllableSshSessionFactory factory)
    {
        var credentials = new FakeCredentialProvider();
        credentials.Add(
            ConnectorHarness.LoginCredential, "key"u8.ToArray(), CredentialKind.SshKey, "labadmin");

        var options = Options.Create(new ConnectorConcurrencyOptions());

        return new SshConnector(
            credentials,
            factory,
            new SshConnectionPool(options),
            new SemaphoreConnectionGovernor(options),
            new KeyedOperationCoordinator(),
            NullLogger<SshConnector>.Instance);
    }
}
