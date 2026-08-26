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

/// <summary>
/// Where an asset — or an observation about one — came from. The canonical copy, shared by
/// <c>assets.source</c> and <c>asset_evidence.source</c> because they are the same vocabulary
/// asked about two different rows.
///
/// <para><b>Only <see cref="Discovery"/> is written today.</b> The other three are what slice 4's
/// correlation will write, and they are in the constraint from the start deliberately: a CHECK
/// admitting only the value that happens to exist would turn the next legitimate write into a
/// Postgres 23514 at the moment correlation first runs.</para>
///
/// <para>Constraining this closes the <c>assets.source</c> part of review <b>M8</b>, open since
/// Phase 1 — five enum-shaped columns typed as unconstrained <c>text</c>, where "the frozen
/// vocabulary is a database contract" was promised and never delivered. The other four
/// (<c>assets.state</c>, <c>findings.state</c>, <c>credentials.kind</c>, <c>tenants.status</c>)
/// are still open and are not Phase 4's to close.</para>
/// </summary>
public static class AssetSources
{
    public const string Discovery = "discovery";
    public const string Ad = "ad";
    public const string Dhcp = "dhcp";
    public const string Inventory = "inventory";

    public static readonly IReadOnlyList<string> All = [Discovery, Ad, Dhcp, Inventory];
}
