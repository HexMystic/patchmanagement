namespace PatchManagement.Api.Tenancy;

/// <summary>
/// Resolves the tenant for a request. The dev implementation reads an <c>X-Tenant-Id</c>
/// header; real authentication (a tenant claim) plugs in here later without touching the
/// middleware or the RLS wiring.
/// </summary>
public interface ITenantResolver
{
    Guid? Resolve(HttpContext context);
}
