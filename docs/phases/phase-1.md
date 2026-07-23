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
- Every table: `tenant_id uuid not null`.
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

## Core tables (representative — expand as needed)
| Table | Key columns (besides `tenant_id`, `id`, timestamps) |
|-------|------|
| `tenants` | name, status *(the only non-tenant-scoped root table)* |
| `operators` | email, role, auth refs *(console users; not endpoint creds)* |
| `credentials` | name, kind(win/ssh), **envelope**(ciphertext), dek_id, target_scope — see Phase 2 |
| `assets` | hostname, ip, os_family, os_version, managed(bool), source(discovery/ad/dhcp), **state** |
| `asset_packages` | asset_id, name, version, epoch, arch, source(pkgmgr) |
| `content_sources` | kind(nvd/kev/epss/usn/rhsa/msrc/wsusscn2), last_sync, cursor |
| `advisories` | source, external_id(CVE/USN/RHSA/…), title, severity, published_at, raw_ref |
| `advisory_affects` | advisory_id, package_name, fixed_version, ecosystem, backported(bool) |
| `patches` | vendor_id(KB/USN/…), title, **reversible**(bool), requires_reboot(bool) |
| `patch_supersedence` | patch_id, superseded_by_patch_id |
| `findings` | asset_id, advisory_id, patch_id, **state**, reversible, risk_score, risk_explanation(jsonb) |
| `deployments` | name, created_by, schedule_id, status |
| `waves` | deployment_id, ordinal, target_group, status |
| `deployment_targets` | wave_id, asset_id, finding_id, **state**, verification(jsonb) |
| `health_probes` | host_group, definition(jsonb), phase(baseline/post) |
| `exceptions` | finding_id/scope, reason, approved_by, expires_at *(risk acceptance)* |
| `schedules` | cron, window, freeze_calendar_ref |
| `audit_log` | actor, action, target, at, detail(jsonb) — **append-only**, never contains secrets |

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
