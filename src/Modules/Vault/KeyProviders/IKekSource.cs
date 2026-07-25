namespace PatchManagement.Vault.KeyProviders;

/// <summary>
/// The cold-start source of the software KEK (THREAT-MODEL "KEK cold-start problem"). When the
/// container restarts unattended, this is where the KEK versions come from — and where a rotation
/// persists the new version so it survives the next restart.
///
/// Implementations (selected by <c>VAULT_SOFTWARE_KEK_SOURCE</c>):
/// <list type="bullet">
///   <item><b>keyfile</b> (default) — <see cref="KeyFileKekSource"/>: a permission-locked file;
///   convenient, supports unattended restart.</item>
///   <item><b>operator</b> — entered by a human on start; strongest, no unattended restart.</item>
///   <item><b>tpm</b> — sealed to hardware/boot state.</item>
/// </list>
/// Only <c>keyfile</c> (and an in-memory source for tests) is implemented in Phase 2; operator/TPM
/// are declared and STUBBED so the config surface is honest about what exists.
///
/// <para><b>There is deliberately no <c>SaveAsync</c>.</b> "Load, mutate, save" is the shape that
/// let two processes overwrite each other's KEK versions with a stale snapshot (review C2). Adding
/// a version is instead one atomic operation the store performs on itself, so the unsafe pattern
/// cannot be expressed by a caller. See ADR 0015.</para>
/// </summary>
public interface IKekSource
{
    /// <summary>Load the KEK keyset, creating an initial one if the store is empty (first boot).</summary>
    Task<KekKeyset> LoadAsync(CancellationToken ct);

    /// <summary>
    /// Atomically add a freshly generated KEK version, make it current, and return the resulting
    /// keyset.
    ///
    /// <para>Implementations must be safe against concurrent callers — including other PROCESSES
    /// sharing the same store — and must not return until the new version is DURABLY stored. The
    /// caller treats the returned keyset as authoritative and will immediately wrap data under its
    /// current version, so a version that is live in memory but absent from the store is
    /// unrecoverable data loss (review C4).</para>
    /// </summary>
    Task<KekKeyset> AddVersionAsync(CancellationToken ct);

    /// <summary>Human-readable description for diagnostics — never includes key material.</summary>
    string Describe();
}
