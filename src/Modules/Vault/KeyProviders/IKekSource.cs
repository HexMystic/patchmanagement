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
/// </summary>
public interface IKekSource
{
    /// <summary>Load the KEK keyset, creating an initial one if the store is empty (first boot).</summary>
    Task<KekKeyset> LoadAsync(CancellationToken ct);

    /// <summary>Persist the keyset (after a rotation adds a version) so it survives a restart.</summary>
    Task SaveAsync(KekKeyset keyset, CancellationToken ct);

    /// <summary>Human-readable description for diagnostics — never includes key material.</summary>
    string Describe();
}
