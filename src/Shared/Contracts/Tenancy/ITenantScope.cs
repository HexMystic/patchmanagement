namespace PatchManagement.Contracts.Tenancy;

/// <summary>
/// A unit of work bound to exactly one tenant, for code running OFF the HTTP path. Resolve services
/// from <see cref="Services"/> and they behave exactly as they would in a request for that tenant —
/// same restricted DB role, same row-level security, same fail-closed policy.
///
/// <para>The tenant is fixed at creation and cannot be changed. That is deliberate: the tenant is
/// applied to the database session when a connection is opened, so reassigning it on a live scope
/// would silently not take effect on a connection already open. One scope, one tenant.</para>
/// </summary>
public interface ITenantScope : IDisposable
{
    /// <summary>The tenant every service resolved from this scope is bound to.</summary>
    Guid TenantId { get; }

    /// <summary>Services scoped to <see cref="TenantId"/>.</summary>
    IServiceProvider Services { get; }
}
