using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Tenancy;

namespace PatchManagement.Persistence.Rls;

/// <summary>
/// Implements <see cref="ITenantScopeFactory"/> against the ordinary request plumbing: it creates a
/// DI scope and pre-sets that scope's <see cref="TenantContextAccessor"/>, which
/// <see cref="RlsConnectionInterceptor"/> then applies to every connection the scope opens. A job
/// therefore gets exactly what a request for that tenant gets — same restricted role, same policy.
///
/// <para><b>No elevation is involved.</b> There is no second connection, no owner or BYPASSRLS role,
/// and no schema change. Cross-tenant work is a sweep of single-tenant scopes; the tenant registry
/// is readable by the app role already and holds no tenant-owned data, so enumerating it grants
/// nothing. See ADR 0014.</para>
/// </summary>
public sealed class TenantScopeFactory(IServiceScopeFactory scopes, ILogger<TenantScopeFactory> logger)
    : ITenantScopeFactory
{
    public ITenantScope Create(Guid tenantId) => new TenantScope(scopes.CreateScope(), tenantId);

    public async Task<IReadOnlyList<Guid>> ListTenantsAsync(CancellationToken ct)
    {
        // No tenant is set here on purpose: `tenants` carries no tenant_id and has no RLS policy, so
        // this reads the registry without any tenant-owned data being reachable.
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        return await db.Tenants.OrderBy(t => t.Id).Select(t => t.Id).ToListAsync(ct);
    }

    public async Task<TenantSweepResult> SweepAsync(
        string operation, Func<ITenantScope, CancellationToken, Task> work, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(work);

        var tenants = await ListTenantsAsync(ct);
        var failures = new List<TenantFailure>();
        var attempted = 0;
        var succeeded = 0;

        foreach (var tenantId in tenants)
        {
            if (ct.IsCancellationRequested) break; // stop cleanly; the partial result says how far we got

            attempted++;
            try
            {
                using var scope = Create(tenantId);
                await work(scope, ct);
                succeeded++;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Do NOT decrement. This tenant was entered, and from here there is no way to know
                // whether its work committed before the cancel landed — the delegate may have saved
                // and then been cancelled during a follow-up write. Un-counting it erased the tenant
                // from BOTH TenantsAttempted and Failures, so a tenant whose rows had actually
                // changed vanished from the result entirely (re-review H-C). Record it by name with
                // the honest verdict instead: attempted, outcome unknown.
                failures.Add(new TenantFailure(
                    tenantId,
                    "OperationCanceledException: cancelled after this tenant's scope started; "
                    + "committed state is unknown"));
                break;
            }
            catch (Exception ex)
            {
                // Isolation is the point: record and keep going, so one tenant cannot halt the sweep.
                failures.Add(new TenantFailure(tenantId, $"{ex.GetType().Name}: {ex.Message}"));
                logger.LogWarning(
                    "System sweep {Operation} failed for tenant {TenantId} ({ExceptionType}); continuing",
                    operation, tenantId, ex.GetType().Name);
            }
        }

        return new TenantSweepResult(tenants.Count, attempted, succeeded, failures);
    }

    /// <summary>Owns the DI scope and fixes its tenant at construction, before anything resolves a
    /// DbContext — the GUC is written when a connection opens, so a later change would not apply.</summary>
    private sealed class TenantScope : ITenantScope
    {
        private readonly IServiceScope _scope;

        public TenantScope(IServiceScope scope, Guid tenantId)
        {
            _scope = scope;
            scope.ServiceProvider.GetRequiredService<TenantContextAccessor>().TenantId = tenantId;
            TenantId = tenantId;
        }

        public Guid TenantId { get; }

        public IServiceProvider Services => _scope.ServiceProvider;

        public void Dispose() => _scope.Dispose();
    }
}
