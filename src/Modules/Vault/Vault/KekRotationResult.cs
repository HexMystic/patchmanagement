using PatchManagement.Contracts.Tenancy;

namespace PatchManagement.Vault.Services;

/// <summary>
/// Outcome of a KEK rotation. Reports what was actually re-wrapped, what was skipped, and what
/// failed — a rotation that silently did nothing must not be indistinguishable from one that worked
/// (review C1), and a partial rotation must be visible as partial (CLAUDE.md §4.6).
/// </summary>
/// <param name="KeyId">The KEK version every DEK was converged onto.</param>
/// <param name="TenantsTotal">Tenants in the registry when the rotation started.</param>
/// <param name="TenantsAttempted">Tenants actually swept; fewer than total means cancellation.</param>
/// <param name="DeksRewrapped">DEKs genuinely re-wrapped — not "DEKs examined".</param>
/// <param name="DeksSkipped">DEKs with no sealed material to re-wrap.</param>
/// <param name="Failures">DEKs that could not be re-wrapped. Each was isolated; the sweep continued.</param>
/// <param name="TenantFailures">
/// Tenants whose scope threw before or around the DEK loop — a dropped connection on the query, a
/// failed save, a failed audit append. Those tenants were NOT rotated at all, which is strictly worse
/// than a single bad DEK, so they must count against <see cref="Complete"/> (re-review H-A).
/// </param>
public sealed record KekRotationResult(
    string KeyId,
    int TenantsTotal,
    int TenantsAttempted,
    int DeksRewrapped,
    int DeksSkipped,
    IReadOnlyList<KekRotationFailure> Failures,
    IReadOnlyList<TenantFailure> TenantFailures)
{
    /// <summary>Always zero — a re-wrap never re-encrypts a credential. Surfaced so the invariant is
    /// visible in logs and tests.</summary>
    public int CredentialsReencrypted => 0;

    /// <summary>
    /// True only if every tenant was swept and every DEK converged. When false, re-running
    /// <see cref="IKekRotationService.CompleteRotationAsync"/> finishes the remainder without
    /// minting another KEK version.
    /// </summary>
    public bool Complete =>
        Failures.Count == 0 && TenantFailures.Count == 0 && TenantsAttempted == TenantsTotal;
}
