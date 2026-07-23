using PatchManagement.Contracts.States;

namespace PatchManagement.Persistence.Entities;

/// <summary>A managed (or discovered-but-unmanaged) endpoint.</summary>
public sealed class Asset
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Hostname { get; set; } = string.Empty;
    public string? Ip { get; set; }
    public string? OsFamily { get; set; }
    public string? OsVersion { get; set; }

    /// <summary>False until inventoried (discovered / correlated but not yet managed).</summary>
    public bool Managed { get; set; }

    /// <summary>Where this asset was first seen: discovery / ad / dhcp / inventory.</summary>
    public string Source { get; set; } = "discovery";

    /// <summary>Current honest lifecycle state.</summary>
    public EndpointState State { get; set; } = EndpointState.ScanFailed;

    public DateTimeOffset? LastSeen { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
