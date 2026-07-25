namespace PatchManagement.Contracts.Tenancy;

/// <summary>
/// One tenant whose work threw during a sweep. <paramref name="Reason"/> is diagnostic metadata —
/// exception type and message — and must never carry secret material (CLAUDE.md NEVER #1).
/// </summary>
public sealed record TenantFailure(Guid TenantId, string Reason);
