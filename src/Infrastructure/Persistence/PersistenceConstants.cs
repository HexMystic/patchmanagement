namespace PatchManagement.Persistence;

/// <summary>Shared identifiers for the RLS wiring (kept in sync with the migration SQL).</summary>
public static class PersistenceConstants
{
    /// <summary>The session GUC that carries the current tenant id for RLS policies.</summary>
    public const string TenantGuc = "app.tenant_id";

    /// <summary>The restricted, non-owner application role the app connects as.</summary>
    public const string AppRole = "patchmgmt_app";
}
