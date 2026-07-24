namespace PatchManagement.Vault.Services;

/// <summary>
/// Rotates the master KEK and re-wraps every tenant's DEK under the new version — WITHOUT touching
/// a single credential envelope (phase-2.md, THREAT-MODEL "rotation is cheap"). This is a
/// privileged, cross-tenant maintenance operation: it must see all tenants' <c>data_keys</c>, so it
/// runs under a maintenance DB context that is not restricted by per-tenant RLS.
/// </summary>
public interface IKekRotationService
{
    Task<KekRotationResult> RotateAsync(CancellationToken ct);
}
