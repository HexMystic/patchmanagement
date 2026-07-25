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
/// <param name="DeksSkipped">
/// Live DEKs with no sealed material to re-wrap. Never a benign condition: every DEK
/// <c>DataKeyService</c> creates is sealed, so a live row without material is a corrupt or tampered
/// one. It counts against <see cref="Complete"/> (cold review H1).
/// </param>
/// <param name="Failures">
/// DEKs that did not converge — whether the re-wrap threw or the row had nothing to re-wrap. Each
/// was isolated and the sweep continued, but every one of them is still on its old KEK version.
/// </param>
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
    /// True only if every tenant was swept and every live DEK converged onto <see cref="KeyId"/>.
    /// When false, re-running <see cref="IKekRotationService.CompleteRotationAsync"/> finishes the
    /// remainder without minting another KEK version.
    ///
    /// <para><b>Treat this signal as guilty until proven.</b> "Reports success while untrue" is this
    /// subsystem's characteristic failure and has now been found four separate times: review C1
    /// (rotated nothing, returned success), re-review H-A (tenant failures ignored here), re-review
    /// CR-1/C-A (destroyed or reversed the estate, returned success), and cold-review H1 (skipped
    /// DEKs ignored here). Note that the H-A fix corrected the *numbers* and left the dishonesty in
    /// this property — fixing the counter is not the same as fixing the verdict. Before changing
    /// this expression, ask what an operator does when it returns <c>true</c> — they stop, and do
    /// not re-run — and who benefits if it is wrong. The four instances are tabulated in
    /// <c>docs/adr/0016-single-process-vault.md</c>, "The recurring hazard".</para>
    ///
    /// <para><c>DeksSkipped</c> is checked as well as <c>Failures</c> even though every skip is also
    /// recorded as a failure. That redundancy is deliberate on a signal with this history: it takes
    /// two independent mistakes, not one, to make this lie again.</para>
    /// </summary>
    public bool Complete =>
        Failures.Count == 0
        && TenantFailures.Count == 0
        && DeksSkipped == 0
        && TenantsAttempted == TenantsTotal;
}
