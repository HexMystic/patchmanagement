namespace PatchManagement.Persistence.Entities;

/// <summary>An installed package on an asset (as inventoried by the connector).</summary>
public sealed class AssetPackage
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid AssetId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;

    /// <summary>RPM epoch, where applicable (dominates version comparison).</summary>
    public int? Epoch { get; set; }
    public string? Arch { get; set; }

    /// <summary>Originating package manager (apt / dnf / …).</summary>
    public string? Source { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}
