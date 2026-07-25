namespace PatchManagement.Vault.Services;

/// <summary>
/// Rotates the master KEK and re-wraps every tenant's DEK under the new version — WITHOUT touching
/// a single credential envelope (phase-2.md, THREAT-MODEL "rotation is cheap").
///
/// <para>This is a privileged, cross-tenant maintenance operation, but it needs no elevated database
/// access: it sweeps tenants one at a time through <c>ITenantScopeFactory</c>, each under the
/// ordinary restricted role with row-level security fully enforced (ADR 0014). It runs off the HTTP
/// path, where nothing sets a tenant — which is precisely why it previously rotated nothing and
/// reported success (review C1).</para>
/// </summary>
public interface IKekRotationService
{
    /// <summary>
    /// Mint a new KEK version and converge every tenant's DEKs onto it. Safe to retry: old versions
    /// are retained, so a DEK not yet re-wrapped still unwraps. Prefer
    /// <see cref="CompleteRotationAsync"/> for a retry, so a partial run does not mint a second key.
    /// </summary>
    Task<KekRotationResult> RotateAsync(CancellationToken ct);

    /// <summary>
    /// Converge any DEK still on an older KEK version onto the CURRENT one, without minting a new
    /// version. This is how a partial rotation is finished — call it after a run whose
    /// <see cref="KekRotationResult.Complete"/> was false, once the underlying cause is resolved.
    /// </summary>
    Task<KekRotationResult> CompleteRotationAsync(CancellationToken ct);
}
