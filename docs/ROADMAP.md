# ROADMAP — Master Plan

The single source of truth for what gets built, in what order, and what "done"
means. Each session starts here: pick the next phase whose dependencies are met,
do the work to its exit criteria, then update its **Status** (see
`docs/WORKFLOW.md`).

**Status values:** `not-started` · `in-progress` · `blocked` · `complete`

**Parallelism:** `solo` phases must be the only phase in flight (they touch shared
contracts or are inherently sequential). `parallel` phases can run concurrently in
separate worktrees. **Phase 8 is solo.**

## Phase summary

| # | Phase | Mode | Depends on | Status |
|---|-------|------|-----------|--------|
| 0 | Environment & design | solo | — | **complete** |
| 1 | Contracts | solo | 0 | not-started |
| 2 | Credential vault | parallel | 1 | not-started |
| 3 | Endpoint connector | parallel | 1 | not-started |
| 4 | Discovery & inventory | parallel | 3 | not-started |
| 5 | Content ingestion | parallel | 1 | not-started |
| 6 | Assessment | solo | 4, 5 | not-started |
| 7 | Risk scoring | parallel | 6 | not-started |
| 8 | Deployment engine | **SOLO** | 6 | not-started |
| 9 | Health probes & auto-rollback | parallel | 8 | not-started |
| 10 | Blast-radius dry run | parallel | 6, 8 | not-started |
| 11 | Scheduling, notifications, reporting | parallel | 6 | not-started |
| 12 | UI | parallel | 1 | not-started |
| 13 | Audit, compliance, evidence | parallel | 6 | not-started |

---

## Phase 0 — Environment & design  · solo · Status: complete
- **Goal:** Working local environment + all Phase-0 governance/design docs. No app code.
- **Dependencies:** none.
- **Exit criteria:** `scripts/verify-env.ps1` all-green; root stack (pg/redis) and
  lab fleet (5 distros) up with SSH verified; `wsusscn2.cab` fetched & gitignored;
  all governance docs (this file, CLAUDE.md, WORKFLOW, HARD-PROBLEMS, THREAT-MODEL,
  DIFFERENTIATORS, ADRs 0001–0008, phase-1..4 specs) present and cross-linked.
- **Owned paths:** `/`, `/lab`, `/scripts`, `/docs`, `.claude/`, `docker-compose.yml`.

## Phase 1 — Contracts  · solo · Status: not-started
- **Goal:** Freeze the foundational contracts everything else depends on.
- **Dependencies:** Phase 0.
- **Exit criteria:** PostgreSQL schema with `tenant_id` on every table + **RLS
  policies**; EF Core model + migrations; OpenAPI spec; JSON schemas for content &
  assessment records; the **honest endpoint state machine** (states + legal
  transitions) encoded and documented; reversible/irreversible patch flag present;
  the **append-only audit interface (`IAuditLog`) + `audit_log` table** defined here
  (see cross-cutting note below).
- **Cross-cutting — audit logging:** audit is a cross-cutting concern, not just the
  Phase 13 module. The **append-only `IAuditLog` interface + `audit_log` table must be
  defined in these Phase 1 contracts** so that **Phase 2's vault can log every
  credential access from day one** (and Phases 3–8 can audit privileged endpoint
  actions as they are built). Phase 13 later delivers the *full* module — retention,
  evidence bundles, compliance exports, UI — on top of this same interface. The
  interface is frozen here; the implementation grows over time.
- **Owned paths:** `src/Shared/Contracts`, `src/Infrastructure/Persistence`,
  `db/migrations`, `docs/phases/phase-1.md`, `api/openapi.yaml`, `schemas/`.
- **Detail:** `docs/phases/phase-1.md`.

## Phase 2 — Credential vault  · parallel · Status: not-started
- **Goal:** Envelope-encrypted credential store; the highest-value asset.
- **Dependencies:** Phase 1.
- **Exit criteria:** `IKeyProvider` with **software default** + opt-in Azure Key
  Vault / AWS KMS / HashiCorp Vault; master-KEK → per-tenant DEK → credential
  envelope; **KEK rotation + DEK re-wrap without re-encrypting credentials**;
  decryption in-memory only; enforced never-log / never-return invariants with
  tests proving them; **every credential access logged via the Phase-1 `IAuditLog`
  from day one** (metadata only — never the secret).
- **Owned paths:** `src/Modules/Vault`.
- **Detail:** `docs/phases/phase-2.md`. See `docs/THREAT-MODEL.md`.

## Phase 3 — Endpoint connector  · parallel · Status: not-started
- **Goal:** `IEndpointConnector` with WinRM and SSH implementations.
- **Dependencies:** Phase 1.
- **Exit criteria:** Provider-neutral connector (bastion vs direct is config, not
  code); every operation idempotent + time-bounded with `CancellationToken`;
  connection pooling/concurrency limits (the scaling wall); integration tests
  against the lab fleet over SSH.
- **Owned paths:** `src/Modules/Connectors`.
- **Detail:** `docs/phases/phase-3.md`. See `docs/adr/0003-cloud-agnostic-connector.md`.

## Phase 4 — Discovery & inventory  · parallel · Status: not-started
- **Goal:** Discover endpoints; build inventory; surface **unmanaged assets**.
- **Dependencies:** Phase 3.
- **Exit criteria:** IP-range sweep; per-host inventory (OS, packages, patch level)
  via connector; unmanaged-asset correlation against AD/DHCP/managed inventory;
  results persisted with tenant scoping.
- **Owned paths:** `src/Modules/Discovery`.
- **Detail:** `docs/phases/phase-4.md`. See `docs/DIFFERENTIATORS.md` (unmanaged assets).

## Phase 5 — Content ingestion  · parallel · Status: not-started
- **Goal:** Ingest authoritative vuln/patch content.
- **Dependencies:** Phase 1.
- **Exit criteria:** Connectors for NVD, CISA KEV, EPSS, Ubuntu USN, RHSA, MSRC,
  and `wsusscn2.cab`; normalized into the Phase-1 content schema; incremental &
  idempotent refresh; provenance recorded per record.
- **Owned paths:** `src/Modules/Content`.
- **See:** `docs/HARD-PROBLEMS.md` (wsusscn2.cab vs MSRC CSAF).

## Phase 6 — Assessment  · solo · Status: not-started
- **Goal:** Correlate inventory ↔ content into findings, and govern which findings are
  actionable (including the exception / risk-acceptance workflow).
- **Dependencies:** Phases 4 & 5.
- **Exit criteria:** CVE↔package correlation; **backport handling** (RHEL/Debian);
  **supersedence** chains; **version comparison** (RPM epochs, Debian revisions,
  Windows build numbers); classify each finding's patch **reversible/irreversible**;
  emit findings in states `assessed-compliant` / `assessed-missing`; **exception /
  risk-acceptance workflow** (HARD-PROBLEMS #7) — first-class `exceptions` (scope:
  finding/asset/group; reason; approver; **expiry**) that move a finding out of
  actionable **without deleting it**, **auto-reopen on expiry**, and are **audited via
  the Phase-1 `IAuditLog`**.
- **Owned paths:** `src/Modules/Assessment`.
- **See:** `docs/HARD-PROBLEMS.md`.

## Phase 7 — Risk scoring  · parallel · Status: not-started
- **Goal:** Explainable per-finding risk score.
- **Dependencies:** Phase 6.
- **Exit criteria:** Score from CVSS + KEV + EPSS + asset exposure/criticality;
  **every score traceable to its inputs** (stored explanation); no black box.
- **Owned paths:** `src/Modules/Risk`.

## Phase 8 — Deployment engine  · **SOLO** · Status: not-started
- **Goal:** Execute patches in controlled waves with verification.
- **Dependencies:** Phase 6.
- **Exit criteria:** Wave planning; pre-flight checks; time-bounded idempotent
  execution over the connector; **post-deploy verification that re-observes state
  (never trusts exit codes)**; states `deploy-in-progress` → `pending-reboot` /
  `deploy-failed` → `verified`.
- **Owned paths:** `src/Modules/Deployment`.
- **Why solo:** touches the connector, assessment, and state machine simultaneously
  and is the riskiest write path; no other phase may be in flight.

## Phase 9 — Health probes & auto-rollback  · parallel · Status: not-started
- **Goal:** Customer-defined health checks with automatic rollback.
- **Dependencies:** Phase 8.
- **Exit criteria:** Per-host-group probes; baseline → patch → re-probe; on failure
  **automatic rollback (reversible patches only), wave halted, finding reopened,
  alert fired**; states `rollback-in-progress` → `rolled-back`.
- **Owned paths:** `src/Modules/Health`.
- **See:** `docs/DIFFERENTIATORS.md`.

## Phase 10 — Blast-radius dry run  · parallel · Status: not-started
- **Goal:** Simulate a deployment before running it.
- **Dependencies:** Phases 6 & 8.
- **Exit criteria:** Report hosts affected, reboots required, pre-flight failures,
  change freezes, estimated bandwidth and maintenance window — with no writes to
  endpoints.
- **Owned paths:** `src/Modules/BlastRadius`.

## Phase 11 — Scheduling, notifications, reporting  · parallel · Status: not-started
- **Goal:** Schedules, alerts, and reports.
- **Dependencies:** Phase 6.
- **Exit criteria:** Hangfire-backed schedules; notification channels; compliance/
  operational reports; all tenant-scoped.
- **Owned paths:** `src/Modules/Scheduling`, `src/Modules/Reporting`.

## Phase 12 — UI  · parallel · Status: not-started
- **Goal:** Operator console.
- **Dependencies:** Phase 1 (contracts) — builds against OpenAPI; integrates with
  later modules as they land.
- **Exit criteria:** React + TS + MUI app; SignalR live updates; explainable risk &
  blast-radius surfaced; never displays raw credentials.
- **Owned paths:** `/web`.

## Phase 13 — Audit, compliance, evidence  · parallel · Status: not-started
- **Goal:** Immutable audit trail + compliance evidence.
- **Dependencies:** Phase 6.
- **Note:** the append-only **`IAuditLog` interface + `audit_log` table are defined in
  Phase 1** and already used by Phase 2's vault (credential-access logging) and later
  phases. This phase delivers the **full module on top of that same interface** —
  retention/immutability guarantees, evidence bundles, compliance exports, and UI — not
  a new audit primitive.
- **Exit criteria:** Append-only audit of every privileged action; evidence bundles
  for verified patches; compliance exports; credentials never appear in any record.
- **Owned paths:** `src/Modules/Audit`.

---

## Session Log

Running record of what each session accomplished, so a future session has continuity
without re-explaining. Newest entry first.

### 2026-07-24 — Phase 0 complete
**Outcome:** Phase 0 (environment & design) complete. Initial commit `e50a171` pushed
to `origin/main` — private repo `github.com/HexMystic/patchmanagement`. Next up:
**Phase 1 (Contracts, solo)**.

**Environment verified:** .NET SDK 9.0.314, Node 24.16.0, npm 11.13, Git 2.54,
PowerShell 7.6.4, Docker 29.6.2 / Compose v5.3.1, WSL2. Installed this session via
winget: .NET 9 SDK + PowerShell 7. `scripts/verify-env.ps1` → all required checks pass.

**Delivered:** repo scaffold; governance/design docs (CLAUDE.md, this ROADMAP,
WORKFLOW, phases/phase-1..4, adr/0001–0008, HARD-PROBLEMS, THREAT-MODEL,
DIFFERENTIATORS); root compose (Postgres 16 + Redis); `/lab` fleet of 5 distros
(Ubuntu 22.04/24.04, Debian 12, Rocky 9, Alma 9) with SSH key-auth + NOPASSWD sudo
verified on `localhost:2201–2205`; `lab-keygen.ps1` + `verify-env.ps1`;
`wsusscn2.cab` (627.7 MB) downloaded to `/lab/content` (gitignored, **not parsed**);
static lab-only guardrail (`.claude/hooks/lab_only_guard.py`) tested.

**Decisions locked (see `docs/adr/`):** 0002 pluggable `IKeyProvider` (software
default; envelope encryption w/ KEK rotation + DEK re-wrap, no credential
re-encryption) · 0003 cloud-agnostic connector (bastion = config) · 0004 split compose
stacks · 0005 in-house CQRS mediator (no MediatR/AutoMapper — commercial in 2025) ·
0006 multi-tenant PostgreSQL RLS from day one · 0007 static lab-only guardrail
(localhost SSH; WinRM denied) · 0008 Windows content = wsusscn2.cab (applicability) +
MSRC CSAF (CVE overlay).

**Outstanding items:**
- **Postgres 16 container not yet running.** Docker Hub's CloudFront CDN persistently
  EOF-ed `postgres:16`'s large layers this session (30+ retries; redis:7 and all 5
  distro bases pulled fine). Non-blocking for Phase 0 (Postgres first used in Phase 1
  migrations). **When the CDN recovers:** `docker pull postgres:16 && docker compose
  up -d`. If it persists, consider `postgres:16-alpine` (smaller layers). Redis is up
  and healthy.
- **Git identity** set repo-locally (`HexMystic` / `aiclaude@securelinkme.net`) — no
  global config changed.
- Line-ending note: `.gitattributes` pins `*.sh`/Dockerfiles/`*.yml` to LF (container
  safety); other text files follow the host `core.autocrlf`.

**For the next session (Phase 1 — Contracts, solo):** read `docs/phases/phase-1.md`;
bring the root stack up first (needs Postgres for migrations + the RLS isolation test).
