namespace PatchManagement.Persistence.Entities;

/// <summary>
/// One edge of the supersedence DAG: <see cref="PatchId"/> is superseded by
/// <see cref="SupersededByPatchId"/> (HARD-PROBLEMS #4).
///
/// GLOBAL CONTENT — no <c>tenant_id</c>, no RLS (CLAUDE.md §4.1 exemption, ADR 0010).
///
/// At assessment, Phase 6 resolves each missing patch to its <b>effective head</b> — the latest
/// non-superseded applicable patch — and deploys that, rather than a chain of redundant installs.
///
/// The composite primary key on the pair IS the idempotency key: re-ingesting the same edge is a
/// no-op upsert rather than a duplicate. The database rejects only SELF-loops (a cheap, always-
/// wrong case); detecting and breaking DEEPER cycles is Phase 6's traversal responsibility, since
/// it needs the whole graph to do it.
/// </summary>
public sealed class PatchSupersedence
{
    public Guid PatchId { get; set; }

    public Guid SupersededByPatchId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public Patch? Patch { get; set; }
    public Patch? SupersededByPatch { get; set; }
}
