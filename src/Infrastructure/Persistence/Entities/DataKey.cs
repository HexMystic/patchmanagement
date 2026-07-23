namespace PatchManagement.Persistence.Entities;

/// <summary>
/// A per-tenant data key (DEK), stored WRAPPED by the master key (KEK). Phase 1 defines the
/// shape; the Phase 2 vault manages wrapping, rotation, and re-wrap (KEK rotation touches only
/// <see cref="WrappedDek"/>/<see cref="KeyId"/> — never the credentials).
/// </summary>
public sealed class DataKey
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }

    /// <summary>The DEK, encrypted by the current KEK version. Set by Phase 2.</summary>
    public byte[]? WrappedDek { get; set; }

    /// <summary>Identifies the KEK version that wrapped this DEK (for zero-downtime rotation).</summary>
    public string? KeyId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RetiredAt { get; set; }
}
