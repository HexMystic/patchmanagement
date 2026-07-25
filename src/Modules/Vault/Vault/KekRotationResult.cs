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
public sealed record KekRotationResult(
    string KeyId,
    int TenantsTotal,
    int TenantsAttempted,
    int DeksRewrapped,
    int DeksSkipped,
    IReadOnlyList<KekRotationFailure> Failures)
{
    /// <summary>Always zero — a re-wrap never re-encrypts a credential. Surfaced so the invariant is
    /// visible in logs and tests.</summary>
    public int CredentialsReencrypted => 0;

    /// <summary>
    /// True only if every tenant was swept and every DEK converged. When false, re-running
    /// <see cref="IKekRotationService.CompleteRotationAsync"/> finishes the remainder without
    /// minting another KEK version.
    /// </summary>
    public bool Complete => Failures.Count == 0 && TenantsAttempted == TenantsTotal;
}
