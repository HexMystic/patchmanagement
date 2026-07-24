# Phase 1 — Contracts (solo)

> Freeze the artifacts every later phase depends on: database schema + RLS, EF
> Core model, OpenAPI, JSON schemas, and the honest endpoint/finding **state
> machine**. Once frozen, these change only by explicit request (CLAUDE.md NEVER
> #6). A fresh session should be able to execute this doc with no other context.

## Objective
Produce the multi-tenant data contract and the state model. **No business logic**
beyond what the contract needs (migrations, RLS, enums, schema validation).

## Deliverables
1. PostgreSQL schema (SQL migrations under `db/migrations/`) — every table carries
   `tenant_id uuid not null` and an RLS policy.
2. EF Core model + initial migration mirroring the SQL (`src/Infrastructure/Persistence`).
3. `api/openapi.yaml` — API surface skeleton (paths, schemas, error envelope).
4. `schemas/*.json` — JSON Schemas for content records and assessment findings.
5. State machine (states + legal transitions) encoded in `src/Shared/Contracts`
   and documented here.
6. Contract interfaces in `src/Shared/Contracts`:
   - **`ICredentialProvider`** — resolve a credential reference to an in-memory-only
     credential. Implemented later by the Phase 2 vault; defining it here lets **Phase
     3's connector build in parallel with a test double** (see `phase-3.md`).
   - **`IAuditLog`** — append-only audit sink. Cross-cutting: **used by Phase 2 from
     day one** to log credential access; the full module is Phase 13. Back it with the
     `audit_log` table (no UPDATE/DELETE grants to the app role → append-only).

## Multi-tenancy & RLS (the core rule)
- Every **tenant-scoped** table: `tenant_id uuid not null`.
- **One named exemption (amended 2026-07-24, C1):** the **global content catalogue** —
  `content_sources`, `advisories`, `advisory_affects`, `patches`, `patch_supersedence` —
  holds public vendor content identical for every tenant. No `tenant_id`, no RLS,
  read-only to `patchmgmt_app`, written only by `patchmgmt_content`, and the exemption
  list is asserted by `RlsConventionTests`. See `docs/adr/0010-global-content-catalogue.md`
  and CLAUDE.md §4.1.
- The app opens a DB session and sets `SET app.tenant_id = '<guid>'` per request
  (via a connection interceptor). Never interpolate tenant_id into queries — rely
  on RLS so a bug cannot leak across tenants.
- Policy template applied to every tenant-scoped table:

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON <t>
  USING      (tenant_id = current_setting('app.tenant_id')::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
```

- A dedicated non-superuser app role (RLS is not enforced for table owners/superusers —
  hence `FORCE`). Migrations run as owner; the app connects as the restricted role.

## Core tables

**Amended 2026-07-24 (C1 resolution).** This list was originally a flat set of 18
"core" tables, all tenant-scoped. Phase 1 delivered 8; the review
(`docs/reviews/phase-1-review.md`, C1) flagged the gap. Resolution: the contract holds
what **crosses module boundaries**, everything else names an owning phase. The three
groups below are the frozen scope of Phase 1.

### Group A — tenant-scoped, delivered in Phase 1 (8)
| Table | Key columns (besides `tenant_id`, `id`, timestamps) |
|-------|------|
| `tenants` | name, status *(the root registry — no `tenant_id`, no RLS; app has SELECT only)* |
| `operators` | email, role, auth refs *(console users; not endpoint creds)* |
| `credentials` | name, kind(win/ssh), **envelope**(ciphertext), dek_id, target_scope — see Phase 2 |
| `data_keys` | per-tenant DEK (wrapped), retired_at — see Phase 2 |
| `assets` | hostname, ip, os_family, os_version, managed(bool), source(discovery/ad/dhcp), **state** |
| `asset_packages` | asset_id, name, version, epoch, arch, source(pkgmgr) |
| `findings` | asset_id, advisory_id, patch_id, **state**, reversible, risk_score, risk_explanation(jsonb) |
| `audit_log` | actor, action, target, at, detail(jsonb) — **append-only**, never contains secrets |

### Group B — global content catalogue, pulled forward into Phase 1 (5)
**No `tenant_id`, no RLS** (CLAUDE.md §4.1 exemption, ADR 0010). Pulled forward because
they sit on the Phase 5 → 6 → 8 seam: deferring them would let three *parallel* phases
each design part of the same contract.

| Table | Key columns |
|-------|------|
| `content_sources` | kind(nvd/kev/epss/usn/rhsa/msrc/wsusscn2) **unique**, enabled, last_sync_at, cursor, last_status, last_error |
| `advisories` | source, external_id(CVE/USN/RHSA/…) **unique together**, title, severity(incl. `unknown`), published_at, cvss_base_score/vector/version, kev_listed, kev_date_added, epss_score/percentile, **provenance(jsonb)**, raw_ref, withdrawn_at |
| `advisory_affects` | advisory_id, package_name, ecosystem(deb/rpm/windows), **platform**, fixed_version *(both raw-as-sourced — ADR 0011)*, backported(bool) |
| `patches` | source, vendor_id(KB/USN/…) **unique together**, title, **reversible**(bool), requires_reboot(bool), classification, **provenance(jsonb)**, withdrawn_at |
| `patch_supersedence` | patch_id, superseded_by_patch_id *(PK on the pair; self-loop CHECK; deep-cycle detection is Phase 6)* |

Content **retires rather than vanishes** (`withdrawn_at`) — no role holds DELETE.

### Group C — deferred, each with a named owner
| Table | Owner | Note |
|-------|-------|------|
| `deployments`, `waves`, `deployment_targets` | **Phase 8** | traversed read-only by Phase 10's simulator, but owned by 8 |
| `health_probes` | **Phase 9** | consumed by Phase 10 |
| `schedules` (cron, window, freeze_calendar_ref) | **Phase 11** | freeze calendar consumed by Phase 10 |
| `exceptions` (scope, reason, approved_by, expires_at) | **Phase 6 — cross-consumer** | read by Phases 7/8/13; **must be frozen at Phase 6's start**, not evolved by its consumers. See ROADMAP. |
| asset provenance/evidence (unmanaged-flag explainability) | **Phase 4** | DIFFERENTIATORS #2 |
| `advisory_patches` (CVE→KB join, HARD-PROBLEMS #1) | **Phase 5** | not in the original 18; `findings` carries `advisory_id` + `patch_id`, so the correlation is expressible per finding until then |

Tables a later phase adds must follow the frozen conventions — `tenant_id`, GRANT to
`patchmgmt_app`, ENABLE + FORCE RLS, `tenant_isolation` policy — which
`RlsConventionTests` now enforces automatically (review H4).

## The honest state machine
Both **assets** and **findings/targets** move only along legal transitions. States:

`unreachable`, `auth-failed`, `scan-failed`, `assessed-compliant`,
`assessed-missing`, `deploy-in-progress`, `deploy-failed`, `pending-reboot`,
`verified`, `rollback-in-progress`, `rolled-back`.

Legal transitions (source → allowed targets):

| From | To |
|------|----|
| *(initial)* | `unreachable`, `auth-failed`, `scan-failed`, `assessed-compliant`, `assessed-missing` |
| `unreachable` | `auth-failed`, `scan-failed`, `assessed-compliant`, `assessed-missing` (retry) |
| `auth-failed` | `unreachable`, `scan-failed`, `assessed-*` (after cred fix/retry) |
| `scan-failed` | `unreachable`, `auth-failed`, `assessed-*` (retry) |
| `assessed-compliant` | `assessed-missing` (new content), `unreachable`/`auth-failed`/`scan-failed` |
| `assessed-missing` | `deploy-in-progress`, `assessed-compliant` (superseded/exception) |
| `deploy-in-progress` | `pending-reboot`, `deploy-failed`, `verified` |
| `pending-reboot` | `verified`, `deploy-failed` |
| `deploy-failed` | `rollback-in-progress` (reversible), `assessed-missing` (retry) |
| `verified` | `assessed-missing` (regression/new content), `rollback-in-progress` (probe fail) |
| `rollback-in-progress` | `rolled-back`, `deploy-failed` |
| `rolled-back` | `assessed-missing` |

Rules: `unreachable`/`auth-failed`/`scan-failed` are **honest failure states** — we
never silently treat an unreachable host as compliant. Rollback targets require the
finding's `reversible = true`; irreversible patches can reach `deploy-failed` but
**not** `rollback-in-progress`. Encode transitions as data + a guard function; make
illegal transitions throw.

## Reversible/irreversible flag
`patches.reversible` is set at ingestion where known and finalised at assessment.
It gates Phase 8/9 rollback. Default `false` (safe) when unknown.

## Exit criteria
- Migrations apply to the root Postgres; RLS proven by a test: session A (tenant 1)
  cannot see tenant 2 rows even with a raw query.
- EF model matches SQL; `dotnet ef migrations` clean.
- `openapi.yaml` validates; `schemas/*.json` validate sample records.
- State-machine guard rejects every illegal transition (unit tests).
- `ICredentialProvider` and `IAuditLog` interfaces compile and are documented; the
  `audit_log` table is append-only (app role has INSERT/SELECT, no UPDATE/DELETE).

## Verify
`docker compose up -d postgres`; run migrations; run the RLS + state-machine tests;
lint the OpenAPI and JSON schemas.
