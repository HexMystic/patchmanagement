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

    /// <summary>
    /// Management port this endpoint is reached on (SSH 22, WinRM 5985/5986), or null for an asset
    /// that arrived from AD/DHCP/import rather than from a sweep.
    ///
    /// <para>Part of the discovery natural key (ADR 0024). Without it the five lab containers, all
    /// published on 127.0.0.1 at different ports, collapse into one asset. It also completes the
    /// address: <c>EndpointTarget</c> has always carried Host AND Port, so the row now records the
    /// coordinate the connector actually uses rather than half of it.</para>
    /// </summary>
    public int? EndpointPort { get; set; }

    /// <summary>Where this asset was first seen: discovery / ad / dhcp / inventory.</summary>
    public string Source { get; set; } = "discovery";

    /// <summary>Current honest lifecycle state.</summary>
    public EndpointState State { get; set; } = EndpointState.ScanFailed;

    public DateTimeOffset? LastSeen { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
