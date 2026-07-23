namespace PatchManagement.Persistence.Entities;

/// <summary>The tenant root. The ONLY table not scoped by <c>tenant_id</c> / RLS.</summary>
public sealed class Tenant
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Status { get; set; } = "active";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
