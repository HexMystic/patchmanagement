using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.States;

namespace PatchManagement.Contracts.Discovery;

/// <summary>
/// Inventories one asset over the connector: OS identity and the installed-package set, persisted
/// against the asset (Phase 4 criterion (d)).
/// </summary>
public interface IInventoryService
{
    Task<InventoryResult> InventoryAsync(Guid assetId, EndpointTarget target, CancellationToken ct);
}

/// <summary>
/// What one inventory attempt established, or failed to.
///
/// <para><b>Failure is typed, not collapsed</b> (criterion (e), HARD-PROBLEMS #8 and #12). A host
/// that refused the credential and a host that did not answer are different problems with different
/// owners — <c>auth-failed</c> sends someone to whoever holds credentials, <c>unreachable</c> sends
/// them to the network team — and conflating them wastes the hour the report is read in. Neither is
/// ever recorded as compliant.</para>
/// </summary>
public sealed record InventoryResult
{
    public required ConnectorOutcome Outcome { get; init; }

    /// <summary>
    /// The state the asset was moved to, or <c>null</c> when inventory SUCCEEDED.
    ///
    /// <para>Null is deliberate and worth reading twice: the frozen Phase-1 state machine has no
    /// "inventoried" state, and inventing one would be a frozen-contract change (NEVER #6). A
    /// successful inventory is recorded as <c>managed = true</c> with a fresh package set and an
    /// advanced <c>last_seen</c> — the compliance states belong to assessment (Phase 6), which is
    /// the only thing entitled to decide whether an asset is compliant.</para>
    /// </summary>
    public EndpointState? State { get; init; }

    public int PackagesRecorded { get; init; }

    public string? OsFamily { get; init; }
    public string? OsId { get; init; }
    public string? OsVersion { get; init; }

    /// <summary>Diagnostic detail. Never a credential, never raw remote output.</summary>
    public string? Detail { get; init; }

    public bool Succeeded => Outcome == ConnectorOutcome.Ok;
}
