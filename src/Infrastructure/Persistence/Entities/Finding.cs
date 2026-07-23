using PatchManagement.Contracts.States;

namespace PatchManagement.Persistence.Entities;

/// <summary>
/// A correlation of an asset against content — "this patch is missing/compliant on this host".
///
/// The lifecycle MUST support reopening: <see cref="ClosedAt"/> is nullable and no DB
/// constraint makes any <see cref="State"/> terminal, so a closed/verified finding can return
/// to <see cref="EndpointState.AssessedMissing"/> on new content, drift, reimaging, or a failed
/// health probe. <see cref="AdvisoryId"/>/<see cref="PatchId"/> are intentionally nullable with
/// NO foreign key yet — the advisories/patches tables are owned by Phases 5/6, which add the FKs.
/// </summary>
public sealed class Finding
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid AssetId { get; set; }

    public Guid? AdvisoryId { get; set; }
    public Guid? PatchId { get; set; }

    public EndpointState State { get; set; } = EndpointState.AssessedMissing;

    /// <summary>Whether the patch is reversible. Gates rollback (Phases 8/9). Default false (safe).</summary>
    public bool Reversible { get; set; }

    public double? RiskScore { get; set; }

    /// <summary>Explainability: the weighted inputs that produced the score, stored as jsonb.</summary>
    public string? RiskExplanation { get; set; }

    public DateTimeOffset OpenedAt { get; set; }

    /// <summary>Set when the finding closes (verified/compliant); CLEARED again on reopen.</summary>
    public DateTimeOffset? ClosedAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
