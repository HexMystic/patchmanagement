namespace PatchManagement.Persistence.Entities;

/// <summary>
/// One append-only audit record (table <c>audit_log</c>). The application DB role is granted
/// INSERT/SELECT only — no UPDATE/DELETE — so history is tamper-evident. Never contains secrets.
/// </summary>
public sealed class AuditLogEntry
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Actor { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public DateTimeOffset At { get; set; }

    /// <summary>Optional structured context, stored as jsonb. Metadata only — never secrets.</summary>
    public string? Detail { get; set; }
}
