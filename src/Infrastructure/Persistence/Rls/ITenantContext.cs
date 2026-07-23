namespace PatchManagement.Persistence.Rls;

/// <summary>
/// The current request's tenant. Supplied by the API's tenant-context middleware and read by
/// <see cref="RlsConnectionInterceptor"/> to scope every DB connection. Null = no tenant set
/// (the RLS policy then denies all rows — fail closed).
/// </summary>
public interface ITenantContext
{
    Guid? TenantId { get; }
}
