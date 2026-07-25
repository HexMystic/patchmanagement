namespace PatchManagement.Contracts.Tenancy;

/// <summary>
/// The sanctioned way to do tenant-scoped work off the HTTP path (Phase-1 review M6, ADR 0014).
/// Background jobs have no request, so nothing sets the tenant — the row-level-security policy then
/// fails closed and a job silently sees nothing and "succeeds". This is the fix, and the one to
/// reuse: Phase 8 wave execution and Phase 11 schedules should consume it rather than each inventing
/// their own.
///
/// <para><b>This is not a privilege escalation.</b> There is no "all tenants" mode. Cross-tenant work
/// is a SWEEP of ordinary single-tenant scopes, each running as the same restricted database role
/// with row-level security fully enforced. Nothing here can read two tenants in one query — the
/// capability simply does not exist. Enumerating tenants needs no privilege either: the tenant
/// registry carries no tenant data and the app role already reads it.</para>
///
/// <para>Out of scope: tenant-NEUTRAL work such as Phase 5 content ingestion, which writes global
/// tables under its own database role and needs no tenant at all (ADR 0010).</para>
/// </summary>
public interface ITenantScopeFactory
{
    /// <summary>Open a scope bound to one tenant — for a job that already knows its target.</summary>
    ITenantScope Create(Guid tenantId);

    /// <summary>Every tenant in the registry. Ids only; no tenant-owned data is read.</summary>
    Task<IReadOnlyList<Guid>> ListTenantsAsync(CancellationToken ct);

    /// <summary>
    /// Run <paramref name="work"/> once per tenant, each in its own scope.
    ///
    /// <para>Each tenant is isolated: a failure is recorded against that tenant and the sweep
    /// continues, so one bad row cannot halt the rest. Cancellation stops cleanly between tenants and
    /// returns a partial result rather than throwing — compare
    /// <see cref="TenantSweepResult.TenantsAttempted"/> with
    /// <see cref="TenantSweepResult.TenantsTotal"/>.</para>
    /// </summary>
    /// <param name="operation">Short name for logs, e.g. <c>kek.rotate</c>.</param>
    Task<TenantSweepResult> SweepAsync(
        string operation, Func<ITenantScope, CancellationToken, Task> work, CancellationToken ct);
}
