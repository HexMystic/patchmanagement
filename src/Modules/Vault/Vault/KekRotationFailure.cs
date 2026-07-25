namespace PatchManagement.Vault.Services;

/// <summary>
/// One DEK that could not be re-wrapped — a corrupt or relocated <c>data_keys</c> row, or a missing
/// KEK version. Recorded and stepped over so a single bad row cannot abort the whole rotation.
/// <paramref name="Reason"/> is diagnostic metadata only, never key material (CLAUDE.md NEVER #1).
/// </summary>
public sealed record KekRotationFailure(Guid TenantId, Guid DataKeyId, string Reason);
