namespace PatchManagement.Persistence.Rls;

/// <summary>Scoped, mutable holder for the current tenant. Middleware sets it per request.</summary>
public sealed class TenantContextAccessor : ITenantContext
{
    public Guid? TenantId { get; set; }
}
