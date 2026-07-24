# DIFFERENTIATORS

Four capabilities that set this product apart. They are built in later phases, but the parts a
later phase **cannot cheaply add** must exist in the contracts before that phase starts, so we
don't retrofit. Each entry states the capability, what it needs in the contracts today, and the
phase that delivers it.

> **Amended 2026-07-24 (C1).** The "Designed in now" lists below originally said *(Phase 1)*
> against every item. Phase 1's frozen scope holds what **crosses module boundaries**; the rest is
> deferred to a **named owning phase**. Each item below now carries its real owner, and the
> authoritative summary is the ownership table at the end of this file — with `phase-1.md`
> Group C as the per-table register.

---

## 1. Health-probe auto-rollback  (delivered Phase 9)
**Capability.** Customer-defined health checks per host group. For each patched host:
**baseline probe → patch → re-probe**. On probe failure: **automatic rollback, the
wave is halted, the finding is reopened, and an alert fires**.
**Designed in now:**
- `health_probes` (host_group, definition jsonb, phase baseline/post) — **Phase 9**, and
  **cross-consumer**: Phase 10's simulator reads it, and 9 and 10 are both `parallel`, so its
  shape must be frozen at Phase 9's start rather than evolved by its consumer.
- **Patches classified `reversible` / `irreversible` at assessment time** (Phase 6),
  stored on `patches`/`findings`; rollback is only attempted for `reversible = true`.
  `patches.reversible` exists **now** (Phase 1) — it gates a destructive operation, so no later
  phase may invent it.
- State machine includes `rollback-in-progress` and `rolled-back`, and a `verified →
  rollback-in-progress` transition for post-probe failure (Phase 1).
- Findings can **reopen** (`verified`/`rolled-back → assessed-missing`).
**Why it matters.** Turns patching from fire-and-hope into a safe, self-healing loop.

## 2. Unmanaged-asset discovery  (delivered Phase 4)
**Capability.** Sweep IP ranges and **correlate against AD, DHCP, and managed
inventory** to surface devices that are **on the network but in no inventory** — the
machines attackers love and existing tools miss.
**Designed in now:**
- `assets.managed` (bool) and `assets.source` (discovery/ad/dhcp/inventory) in Phase 1.
- Provenance/evidence linkage so an unmanaged flag is **explainable** (seen at IP X by
  sweep, DHCP lease Y, absent from AD/inventory).
**Why it matters.** Coverage gaps are the real risk; we make them visible, with proof.

## 3. Blast-radius dry run  (delivered Phase 10)
**Capability.** Before any deployment, **simulate** it: hosts affected, reboots
required, pre-flight failures, change freezes in effect, and estimated bandwidth and
maintenance window — with **zero writes** to endpoints.
**Designed in now:**
- Deterministic wave/target modeling (`deployments`, `waves`, `deployment_targets`) that the
  simulator can traverse read-only — **Phase 8** owns these; Phase 10 only reads them.
- `patches.requires_reboot` and reversibility exist **now** (Phase 1), so a simulation can be
  accurate the moment there are waves to traverse. The freeze-calendar reference on `schedules`
  is **Phase 11**, and **cross-consumer** (Phase 10 reads it; 10 and 11 are both `parallel`), so
  it must be frozen at Phase 11's start.
**Why it matters.** Operators approve change with eyes open; no surprise reboots.

## 4. Explainable risk scoring  (delivered Phase 7)
**Capability.** Every risk score is **traceable to its inputs** — CVSS, KEV
membership, EPSS probability, asset exposure/criticality. **No black box.**
**Designed in now:**
- `findings.risk_score` **and** `findings.risk_explanation` (jsonb) in Phase 1 — the
  explanation (the weighted inputs that produced the score) is stored *with* the
  score, not recomputed or hidden.
- Content schema retains KEV/EPSS/CVSS provenance per advisory so inputs are auditable.
**Why it matters.** Security teams act on scores they can defend; auditors can verify
them.

---

**Cross-cutting rule (amended 2026-07-24 — C1 resolution).** None of these are
bolt-ons: every field a *later* phase cannot cheaply add must exist in the contract
before that phase starts. The original wording required **all** fields above to exist
before Phase 1 was marked complete. That gate was unachievable at Phase 1's agreed
foundational scope and contradicted the delivery, so it is replaced by the ownership
table below: the contract holds everything that **crosses module boundaries** (and so
would otherwise be designed twice by parallel phases), and each remaining field names
the single phase that owns it.

| # | Differentiator | In the contract now | Deferred to (owner) |
|---|---|---|---|
| 1 | Health-probe auto-rollback | state machine (`rollback-in-progress`, `rolled-back`, `verified → rollback-in-progress`), `findings.reversible`, **`patches.reversible`** | `health_probes` → **Phase 9** |
| 2 | Unmanaged-asset discovery | `assets.managed`, `assets.source` | provenance/evidence linkage (explainable unmanaged flag) → **Phase 4** |
| 3 | Blast-radius dry run | **`patches.requires_reboot`**, `patch_supersedence` DAG, reversibility | `deployments`/`waves`/`deployment_targets` → **Phase 8** (traversed read-only by Phase 10); `schedules` + freeze calendar → **Phase 11** |
| 4 | Explainable risk scoring | `findings.risk_score`, `findings.risk_explanation`, **advisory CVSS/KEV/EPSS + required `provenance`** | scoring weights & `IVersionComparator`-style explanation shape → **Phase 7** |

**The gate that replaces it.** Before a phase in the "Deferred to" column starts, its
row must be re-read: if the table it owns is read by *any phase other than its owner*, it
is contract-shaped and must be **frozen at that phase's start**, not evolved piecemeal.
Deferring is allowed; deferring **without a named owner** is not.

**The cross-consumer set** — deferred tables whose owner is not their only consumer. Each is a
place C1 can repeat, so each is named rather than left to be discovered:

| Table | Owner (freezes it) | Also read by | Why it bites |
|---|---|---|---|
| `exceptions` | **Phase 6** (`solo`) | 7 (score suppression), 8 (target exclusion), 13 (compliance export) | three consumers, none of which may extend it |
| `health_probes` | **Phase 9** (`parallel`) | 10 (`parallel`) | 9 and 10 can be in flight together |
| `schedules` / freeze calendar | **Phase 11** (`parallel`) | 10 (`parallel`) | same — 10 and 11 can run concurrently |
| `deployments` / `waves` / `deployment_targets` | **Phase 8** (`SOLO`) | 10 | Phase 8 is solo, so the freeze is naturally enforced |

`exceptions` is the sharpest case (three consumers) but not the only one: `health_probes` and
`schedules` are each owned by a `parallel` phase and read by another `parallel` phase, which is
precisely the "two sessions guess differently" failure C1 describes.
