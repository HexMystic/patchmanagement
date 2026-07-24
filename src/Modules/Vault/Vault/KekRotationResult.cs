namespace PatchManagement.Vault.Services;

/// <summary>
/// Outcome of a KEK rotation: the new KEK version and how many DEKs were re-wrapped under it.
/// Credentials touched is always zero — a re-wrap never re-encrypts a credential — and is surfaced
/// explicitly so the invariant is visible in logs and tests.
/// </summary>
public sealed record KekRotationResult(string NewKeyId, int DeksRewrapped, int TenantsAffected)
{
    public int CredentialsReencrypted => 0;
}
