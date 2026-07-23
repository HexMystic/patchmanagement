using PatchManagement.Persistence.Rls;

namespace PatchManagement.Api.Tenancy;

/// <summary>
/// Resolves the request's tenant and writes it into the scoped <see cref="TenantContextAccessor"/>,
/// which <c>RlsConnectionInterceptor</c> then applies to every DB connection. This is what lets RLS
/// be proven through a real request pipeline, not only at the DbContext layer. If no tenant is
/// resolved, the accessor stays null and RLS denies all rows (fail closed).
/// </summary>
public sealed class TenantContextMiddleware(RequestDelegate next)
{
    public async Task Invoke(HttpContext context, ITenantResolver resolver, TenantContextAccessor tenant)
    {
        tenant.TenantId = resolver.Resolve(context);
        await next(context);
    }
}
