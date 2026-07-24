namespace PatchManagement.Persistence.Entities;

/// <summary>
/// An installable patch/update — the thing a deployment actually installs, as distinct from an
/// <see cref="Advisory"/> (why it matters).
///
/// GLOBAL CONTENT — no <c>tenant_id</c>, no RLS (CLAUDE.md §4.1 exemption, ADR 0010).
/// Mirrors <c>schemas/patch.schema.json</c>.
/// </summary>
public sealed class Patch
{
    public Guid Id { get; set; }

    /// <summary>nvd / kev / epss / usn / rhsa / msrc / wsusscn2. Unique with <see cref="VendorId"/>.</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>The vendor's patch id: KB5034441, USN-6789-1, RHSA-2025:0001.</summary>
    public string VendorId { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Whether the patch can be uninstalled. GATES ROLLBACK (Phases 8/9): an irreversible patch
    /// may reach <c>deploy-failed</c> but never <c>rollback-in-progress</c>. Defaults to FALSE
    /// when unknown, because false is the safe answer (DIFFERENTIATORS #1, phase-1.md).
    /// </summary>
    public bool Reversible { get; set; }

    /// <summary>
    /// Feeds the blast-radius dry run's reboot count and maintenance-window estimate
    /// (DIFFERENTIATORS #3). Defaults to false when unknown.
    /// </summary>
    public bool RequiresReboot { get; set; }

    /// <summary>Vendor's own category, raw as sourced — sources disagree on taxonomy, so not normalized.</summary>
    public string? Classification { get; set; }

    public DateTimeOffset? PublishedAt { get; set; }

    /// <summary>Set when the vendor pulls the patch. Content retires; it is never deleted.</summary>
    public DateTimeOffset? WithdrawnAt { get; set; }

    /// <summary>
    /// jsonb ARRAY (never null, never empty) — same shape as <see cref="Advisory.Provenance"/>, so
    /// "which source told us this patch is reversible?" is always answerable. MUST be valid JSON.
    /// </summary>
    public string Provenance { get; set; } = "[]";

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
