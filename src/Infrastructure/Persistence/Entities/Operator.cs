namespace PatchManagement.Persistence.Entities;

/// <summary>A console user belonging to a tenant (NOT an endpoint credential).</summary>
public sealed class Operator
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string? ExternalAuthRef { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
