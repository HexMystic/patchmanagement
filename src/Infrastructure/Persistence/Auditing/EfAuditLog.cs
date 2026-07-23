using PatchManagement.Contracts.Auditing;
using PatchManagement.Persistence.Entities;

namespace PatchManagement.Persistence.Auditing;

/// <summary>
/// Writes audit records to the append-only <c>audit_log</c> table. The application DB role has
/// INSERT/SELECT only on that table, so an attempt to alter history fails at the database.
/// </summary>
public sealed class EfAuditLog(AppDbContext db) : IAuditLog
{
    public async Task AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        db.AuditLog.Add(new AuditLogEntry
        {
            Id = Guid.NewGuid(),
            TenantId = entry.TenantId,
            Actor = entry.Actor,
            Action = entry.Action,
            Target = entry.Target,
            At = entry.At,
            Detail = entry.Detail,
        });
        await db.SaveChangesAsync(ct);
    }
}
