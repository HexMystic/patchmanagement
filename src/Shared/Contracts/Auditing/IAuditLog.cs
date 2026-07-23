namespace PatchManagement.Contracts.Auditing;

/// <summary>
/// The append-only audit sink. Cross-cutting: defined in Phase 1 so the Phase 2 vault can
/// log every credential access from day one, and Phases 3–8 can audit privileged endpoint
/// actions. The full audit module (retention, evidence bundles, exports) is Phase 13 and
/// builds on THIS interface — it is frozen here.
///
/// Implementations write to the append-only <c>audit_log</c> table; the application DB role
/// has INSERT/SELECT only (no UPDATE/DELETE), so records cannot be altered after the fact.
/// </summary>
public interface IAuditLog
{
    /// <summary>Append one audit record. Never include secret material in <paramref name="entry"/>.</summary>
    Task AppendAsync(AuditEntry entry, CancellationToken ct);
}
