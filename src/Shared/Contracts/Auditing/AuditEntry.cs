namespace PatchManagement.Contracts.Auditing;

/// <summary>
/// One append-only audit record. Captures WHO did WHAT to WHICH target and WHEN, plus an
/// optional structured <see cref="Detail"/> (JSON). It carries <b>metadata only</b> and must
/// NEVER contain a credential, secret, or decrypted material (CLAUDE.md NEVER #1).
/// </summary>
public sealed record AuditEntry(
    Guid TenantId,
    string Actor,
    string Action,
    string Target,
    DateTimeOffset At,
    string? Detail = null);
