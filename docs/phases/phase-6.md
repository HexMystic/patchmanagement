# Phase 6 — Assessment (solo)

> Correlate inventory ↔ content into findings, and govern which findings are actionable.
> A fresh session can execute this doc standalone. Depends on Phase 4 (inventory) and
> Phase 5 (content). **Solo** — it freezes the correlation and comparison layer.

## Objective
Turn "what is installed" (Phase 4) and "what is published" (Phase 5) into honest findings:
which assets are missing which patches, which are compliant, and which have been
deliberately excepted — each traceable to the inputs that produced it (CLAUDE.md §4.6).

## Scope
- **CVE ↔ package correlation** across the catalogue and `asset_packages`.
- **Backport handling** (RHEL/Debian) — HARD-PROBLEMS #2.
- **Supersedence** resolution to an effective head — HARD-PROBLEMS #4.
- **Version comparison** with exact native semantics — HARD-PROBLEMS #3.
- Classify each finding's patch **reversible / irreversible**.
- Emit findings in `assessed-compliant` / `assessed-missing`.
- **Exception / risk-acceptance workflow** — HARD-PROBLEMS #7.

## The comparator layer must be ecosystem-extensible (ADR 0019)

This is a **hard structural requirement, not a nicety**, and it is the one thing Phase 6 owes to a
decision taken outside it.

[ADR 0019](../adr/0019-third-party-application-vocabulary.md) widened
`advisory_affects.ecosystem` to admit **`app`** — a generic third-party application category — after
the 2026-08-18 audit found that third-party application patching was the product's largest
competitive gap and that the frozen vocabulary could not represent it. That decision was taken
**before this phase deliberately**, because Phase 6 is where comparison semantics freeze: a
comparator layer written around exactly three OS ecosystems makes adding a fourth a rewrite rather
than a registration.

**Phase 6 is NOT required to implement an `app` comparator.** Application version semantics are
Phase 16's problem, and HARD-PROBLEMS #3 holds that an ecosystem needs a comparator before it needs
a row. What Phase 6 **is** required to do is not foreclose it:

- `IVersionComparator` implementations are **resolved by ecosystem at runtime** — a registry or DI
  keyed on the ecosystem string — never a `switch` over three literals, and never three call sites
  each doing their own dispatch.
- An **unrecognised ecosystem fails loudly**. It must not fall back to string or semver compare, and
  it must not be silently treated as compliant. HARD-PROBLEMS #3 is explicit that a generic compare
  is wrong for all three OS ecosystems; it is no less wrong for a fourth. `deb`, `rpm` and `windows`
  are the three implemented; `app` resolving to "no comparator registered" is the **correct**
  behaviour for this phase, and it must be an honest, visible failure.
- Adding the fourth comparator later must touch **the new comparator and its registration only** —
  no change to correlation, to supersedence resolution, or to the finding emitter.

## Data
Extends Phase 1: `findings` (asset ↔ advisory/patch, state, evidence), and first-class
`exceptions` (scope: finding / asset / group; reason; approver; **expiry**).

## Exit criteria
A criterion is met only when a named test proves it — never because the code looks right.

| # | Criterion | Notes |
|---|-----------|-------|
| a | CVE ↔ package correlation produces findings against the lab fleet's real inventory | end-to-end, Phases 4+5 feeding it |
| b | **Backport handling** — a backported fix is not reported missing | HARD-PROBLEMS #2; RHEL and Debian both |
| c | **Supersedence resolves to an effective head**, and **terminates on a cyclic graph** | HARD-PROBLEMS #4. **D-503 blocks this**: `patch_supersedence` accepts a 2-cycle today and the head walk does not terminate on one. Cannot be claimed until it does |
| d | **Version comparison** with exact native semantics, over a conformance corpus from real advisories | RPM epochs, Debian revisions/tildes, Windows build thresholds |
| e | **The comparator layer is ecosystem-extensible** — comparators resolve by ecosystem, and an unregistered ecosystem (`app`) fails loudly rather than falling back | **ADR 0019.** Prove it with a test that registers a stub comparator for a new ecosystem WITHOUT editing correlation or supersedence, and one asserting `app` fails visibly today |
| f | Each finding classifies its patch **reversible / irreversible** | feeds Phase 8/9 rollback |
| g | Findings emit in `assessed-compliant` / `assessed-missing` honestly | see M1 below — the conflation must be resolved first |
| h | **Exception workflow**: scope, reason, approver, expiry; moves a finding out of actionable **without deleting it**; **auto-reopens on expiry**; **audited via `IAuditLog`** | HARD-PROBLEMS #7 |
| i | Every finding is **explainable** — traceable to the inventory row, the advisory and the comparison that produced it | CLAUDE.md §4.6 |

## Inherited blockers — decide or resolve these on entry

| Item | What it is | Why it lands here |
|---|---|---|
| **M1** | Exception / superseded state is conflated with `assessed-compliant` | A **Phase-6-entry decision** from the Phase 1 review. A host that is compliant and a host whose finding was excepted are not the same fact, and reporting them identically is the dishonesty class HARD-PROBLEMS #8 exists to prevent. Criterion (g) depends on it |
| **D-503** | `patch_supersedence` accepts a 2-cycle; the effective-head walk does not terminate on it | Phase 5 deliberately does not reject cyclic content — a real feed can contradict itself and good content must not be refused over it — so cycle-breaking is assessment's job. Blocks criterion (c) |
| **D-501** | `ContentPostgresFixture` duplicates `PatchManagement.IntegrationTests.PostgresFixture` | Phase 6 is the third consumer, which is the point at which the shared fixture gets built rather than argued about |
| **ADR 0018 residual** | The `AppDbContext` CHECK-constraint copy is not covered by `ContentVocabularyTests` | Collapsing it changes what a migration emits — a NEVER #6 question. ADR 0019 has now widened that copy, so the divergence risk it names is live |

## Owned paths
`src/Modules/Assessment`.

## See
`docs/HARD-PROBLEMS.md` (#2, #3, #4, #7, #8) ·
[ADR 0019](../adr/0019-third-party-application-vocabulary.md) ·
[ADR 0011](../adr/0011-fixed-version-raw-as-sourced.md) — `fixed_version`/`platform` are stored raw,
so parsing them is this phase's job.
