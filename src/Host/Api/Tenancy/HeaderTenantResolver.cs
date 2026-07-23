namespace PatchManagement.Api.Tenancy;

/// <summary>
/// DEV tenant resolver: reads the tenant id from the <c>X-Tenant-Id</c> request header.
/// Replace with an auth-claim resolver before production — this trusts the caller.
/// </summary>
public sealed class HeaderTenantResolver : ITenantResolver
{
    public const string HeaderName = "X-Tenant-Id";

    public Guid? Resolve(HttpContext context) =>
        context.Request.Headers.TryGetValue(HeaderName, out var value)
        && Guid.TryParse(value.ToString(), out var tenantId)
            ? tenantId
            : null;
}
