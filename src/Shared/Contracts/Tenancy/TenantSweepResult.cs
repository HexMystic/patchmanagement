namespace PatchManagement.Contracts.Tenancy;

/// <summary>
/// Outcome of a cross-tenant sweep. Reports what was actually done rather than just "no exception":
/// a sweep can finish having skipped tenants that failed, and a caller must be able to tell that
/// from a clean run (CLAUDE.md §4.6 — no unexplained numbers).
/// </summary>
/// <param name="TenantsTotal">Tenants in the registry when the sweep started.</param>
/// <param name="TenantsAttempted">Tenants actually entered — fewer than total means cancellation.</param>
/// <param name="TenantsSucceeded">Tenants whose work completed without an unhandled error.</param>
/// <param name="Failures">One entry per tenant whose work threw. The sweep continued past each.</param>
public sealed record TenantSweepResult(
    int TenantsTotal,
    int TenantsAttempted,
    int TenantsSucceeded,
    IReadOnlyList<TenantFailure> Failures)
{
    /// <summary>True only if every tenant was attempted and none failed.</summary>
    public bool Complete => Failures.Count == 0 && TenantsAttempted == TenantsTotal;
}
