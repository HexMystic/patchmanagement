using System.Text;
using Microsoft.Extensions.DependencyInjection;
using PatchManagement.Contracts.Auditing;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Contracts.Tenancy;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Cancellation must not make a sweep lie about what it did (re-review H-B, H-C). Both defects are
/// the same shape as review C1 and re-review H-A — work that happened, reported as work that did
/// not, or the reverse — which is the class of defect this module has produced three times.
///
/// <para>These run on the shared fixture and deliberately assert nothing about WHICH tenant the
/// sweep reaches first: a sweep visits every tenant in its database, and other classes seed their
/// own. Every assertion below holds regardless of ordering or tenant count.</para>
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class RotationCancellationTests(PostgresFixture fx)
{
    private readonly Guid Tenant = Guid.NewGuid();

    /// <summary>
    /// H-C. The factory cannot know whether a cancelled tenant's work committed, so it must not
    /// claim it never started. Before the fix, <c>attempted--</c> erased the tenant from BOTH
    /// <c>TenantsAttempted</c> and <c>Failures</c> — a tenant whose DEKs had moved and whose audit
    /// had been cancelled simply vanished from the result.
    /// </summary>
    [Fact]
    public async Task A_tenant_cancelled_mid_flight_is_reported_not_erased()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(Tenant, "cancel-mid-flight");

        using var provider = harness.HostLikeContainer();
        var scopes = provider.GetRequiredService<ITenantScopeFactory>();

        using var cts = new CancellationTokenSource();
        var entered = 0;

        var result = await scopes.SweepAsync("test.cancel", (scope, token) =>
        {
            // Stand in for "this tenant did durable work, and then the caller cancelled".
            entered++;
            cts.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }, cts.Token);

        Assert.Equal(1, entered);
        Assert.Equal(1, result.TenantsAttempted);
        Assert.Equal(0, result.TenantsSucceeded);

        // Named, not merely counted — CLAUDE.md §4.6: no unexplained numbers.
        var failure = Assert.Single(result.Failures);
        Assert.Contains("cancel", failure.Reason, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// H-B. The audit row compensates for a re-wrap that is ALREADY committed — it is a second
    /// transaction, because <c>EfAuditLog</c> saves the shared context. Handing it the sweep's token
    /// meant a cancel landing between the two writes committed the key change and dropped its only
    /// record. Probing the vault would leave no trail precisely when someone was probing it.
    /// </summary>
    [Fact]
    public async Task The_audit_that_follows_a_committed_rewrap_cannot_be_cancelled()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(Tenant, "audit-token");
        await StoreAsync(harness, Tenant); // a DEK to move, so the audit path is reached

        var recording = new RecordingAuditLog();
        using var provider = harness.HostLikeContainer(
            configure: s => s.AddScoped<IAuditLog>(_ => recording));

        // A cancellable token that is never cancelled: the rotation completes normally, but the
        // token it threads is one that COULD be cancelled — which is what the old code forwarded.
        using var cts = new CancellationTokenSource();
        var result = await provider.GetRequiredService<IKekRotationService>().RotateAsync(cts.Token);

        Assert.True(result.DeksRewrapped >= 1, "expected at least this test's DEK to move");

        var rotations = recording.Appends.Where(a => a.Entry.Action == "kek.rotate").ToList();
        Assert.NotEmpty(rotations);
        Assert.All(rotations, a => Assert.False(
            a.Token.CanBeCanceled,
            "the audit for an already-committed re-wrap was handed a cancellable token"));
    }

    private static async Task StoreAsync(VaultTestHarness harness, Guid tenantId)
    {
        var secret = Encoding.UTF8.GetBytes("cancel-" + Guid.NewGuid());
        await using var db = harness.AppContext(tenantId);
        await harness.Provider(db, tenantId).StoreAsync(
            new StoreCredentialRequest("cx", CredentialKind.SshKey, secret), CancellationToken.None);
    }
}
