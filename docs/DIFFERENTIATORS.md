# DIFFERENTIATORS

Four capabilities that set this product apart. They are built in later phases, but
**must be designed into the schema and state machine now** (Phase 1) so we don't
retrofit. Each entry states the capability, what it needs in the contracts today,
and the phase that delivers it.

---

## 1. Health-probe auto-rollback  (delivered Phase 9)
**Capability.** Customer-defined health checks per host group. For each patched host:
**baseline probe → patch → re-probe**. On probe failure: **automatic rollback, the
wave is halted, the finding is reopened, and an alert fires**.
**Designed in now:**
- `health_probes` (host_group, definition jsonb, phase baseline/post) in Phase 1.
- **Patches classified `reversible` / `irreversible` at assessment time** (Phase 6),
  stored on `patches`/`findings`; rollback is only attempted for `reversible = true`.
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
- Deterministic wave/target modeling (`deployments`, `waves`, `deployment_targets`)
  that the simulator can traverse read-only (Phase 1).
- `patches.requires_reboot`, freeze-calendar reference on schedules, and reversibility
  — all present in the contract so the simulation is accurate.
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

**Cross-cutting rule.** None of these are bolt-ons. The Phase 1 contract review must
confirm every field above exists before Phase 1 is marked complete — otherwise the
differentiators become expensive retrofits.
