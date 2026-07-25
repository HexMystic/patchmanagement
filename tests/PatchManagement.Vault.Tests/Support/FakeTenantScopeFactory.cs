using PatchManagement.Contracts.Tenancy;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// A hand-written <see cref="ITenantScopeFactory"/> that reports a TENANT-level failure without
/// running the callback — the one failure shape no real-database test can inject, because it means
/// the scope body threw before touching a DEK (a dropped connection on `ToListAsync`, a failed
/// `SaveChanges`, a failed audit append).
///
/// <para>It exists to prove the rotation result reflects those failures rather than only per-DEK
/// ones (re-review H-A).</para>
/// </summary>
public sealed class FakeTenantScopeFactory(TenantSweepResult result) : ITenantScopeFactory
{
    public ITenantScope Create(Guid tenantId) =>
        throw new NotSupportedException("This fake reports a sweep outcome; it creates no scopes.");

    public Task<IReadOnlyList<Guid>> ListTenantsAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<Guid>>([]);

    /// <summary>Returns the canned outcome without invoking <paramref name="work"/>.</summary>
    public Task<TenantSweepResult> SweepAsync(
        string operation, Func<ITenantScope, CancellationToken, Task> work, CancellationToken ct) =>
        Task.FromResult(result);
}
