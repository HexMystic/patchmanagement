namespace PatchManagement.Vault.Services;

/// <summary>
/// Supplies the "who" for audit records the vault writes. In Phase 2 there is no authenticated
/// principal wired into the module, so the default answers <c>"vault"</c>; later phases replace the
/// registration with one that returns the operator identity from the request. Auditing every
/// credential access is a hard requirement (THREAT-MODEL), so we record WHO from day one even while
/// that value is coarse.
/// </summary>
public interface IVaultActor
{
    string Name { get; }
}

/// <summary>Default actor when no authenticated principal is available.</summary>
public sealed class SystemVaultActor : IVaultActor
{
    public string Name => "vault";
}
