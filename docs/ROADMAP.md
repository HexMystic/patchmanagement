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
| 1 | Contracts | solo | 0 | **complete\*** |
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

**\*Phase 1** is complete for the *amended* scope (see C1 below). **C1 is resolved** and the C1
slice closes **H2/H3/H4** as well; the asterisk stays until that slice clears a fresh-session
review against `docs/reviews/phase-1-review.md`. **H1 (no auth/RBAC on any phase), H5 (OpenAPI
freeze inversion), M1–M9 and L1–L7 remain open.** The Phases 2/3/5 fan-out unblocks once the
review clears.

---

## Phase 0 — Environment & design  · solo · Status: complete
- **Goal:** Working local environment + all Phase-0 governance/design docs. No app code.
- **Dependencies:** none.
- **Exit criteria:** `scripts/verify-env.ps1` all-green; root stack (pg/redis) and
  lab fleet (5 distros) up with SSH verified; `wsusscn2.cab` fetched & gitignored;
  all governance docs (this file, CLAUDE.md, WORKFLOW, HARD-PROBLEMS, THREAT-MODEL,
  DIFFERENTIATORS, ADRs 0001–0008, phase-1..4 specs) present and cross-linked.
- **Owned paths:** `/`, `/lab`, `/scripts`, `/docs`, `.claude/`, `docker-compose.yml`.

## Phase 1 — Contracts  · solo · Status: complete
- **Goal:** Freeze the foundational contracts everything else depends on.
- **Dependencies:** Phase 0.
- **Exit criteria** *(amended 2026-07-24, C1)*: PostgreSQL schema with `tenant_id` +
  **RLS policies** on every **tenant-scoped** table, and the **global content catalogue**
  (`content_sources`, `advisories`, `advisory_affects`, `patches`, `patch_supersedence`)
  carrying no `tenant_id` and no RLS, isolated by role instead and **asserted by test**
  (ADR 0010, CLAUDE.md §4.1); EF Core model + migrations; **referential integrity**
  (composite tenant-consistent FKs); OpenAPI spec; JSON schemas for content &
  assessment records; the **honest endpoint state machine** (states + legal
  transitions) encoded and documented; reversible/irreversible patch flag present;
  the **append-only audit interface (`IAuditLog`) + `audit_log` table** defined here
  (see cross-cutting note below). Tables outside the frozen scope are deferred **with a
  named owning phase** — see `phase-1.md` Group C.
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
- **Exit criteria:** Connectors for NVD, CISA KEV, EPSS, Ubuntu USN, **Debian DSA**, RHSA,
  MSRC, and `wsusscn2.cab`; normalized into the Phase-1 content schema; incremental &
  idempotent refresh; provenance recorded per record.
- **Owned paths:** `src/Modules/Content`.
- **See:** `docs/HARD-PROBLEMS.md` (wsusscn2.cab vs MSRC CSAF; #2/#3 require Debian DSA).
- **Content vocabulary is frozen in Phase 1** (`advisories.source`, `patches.source`,
  `content_sources.kind`, `ecosystem`) and covers every feed above plus the lab fleet
  (Ubuntu→USN, Debian→DSA, Rocky/Alma→RHSA, Windows→MSRC+wsusscn2). Two deferred, both
  Phase-5-owned and **additive** (never a change to the frozen five): NVD affected-version
  *ranges* (`advisory_ranges`), and native Rocky/Alma errata (**RLSA/ALSA**) *if* per-rebuild
  version precision proves necessary — until then Rocky/Alma are assessed against `rhsa`, which
  is the RHEL content they rebuild (see `phase-1.md` Group B note).

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

## Phase 1 review — follow-ups (OPEN)

Source: `docs/reviews/phase-1-review.md`, reviewed at commit `fb7b4b5`.
Verdict summary: the RLS work, the state machine, and the append-only audit grants hold up;
the gap is what the frozen contract *didn't* include.

### C1 — RESOLVED 2026-07-24 (option b + partial pull-forward)
**Decision:** formally amend `DIFFERENTIATORS.md` + `phase-1.md` + `CLAUDE.md` §4.1 to the
foundational scope, **and** pull forward the five tables that cross module boundaries and would
otherwise be designed twice by parallel phases: `content_sources`, `advisories`,
`advisory_affects`, `patches`, `patch_supersedence`. Everything else deferred **with a named
owner** (`phase-1.md` Group C). Delivered in the C1 slice — see the Session Log entry.

**Tenancy — the content catalogue is global (ADR 0010).** `phase-1.md` and CLAUDE.md §4.1 both
specified *every* table as tenant-scoped, so this is a deliberate constitution amendment, not a
gap-fill: content is public vendor data, identical per tenant, and per-tenant copies would force
Phase 5's sync into a per-tenant loop it has no tenant context for (M6). The five tables carry no
`tenant_id` and no RLS, are read-only to `patchmgmt_app`, and are written only by the new
`patchmgmt_content` role. The exemption is **asserted by `RlsConventionTests`** (not a silent
gap): a sixth global table fails the test until someone edits the list and defends it.

**`exceptions` is deferred AND cross-consumer — not single-owner.** Phase 6 creates it, but
Phase 7 (score suppression), Phase 8 (target exclusion) and Phase 13 (compliance export) all read
it. Its shape must therefore be **frozen at the start of Phase 6** (which is `solo`) and **not**
evolved piecemeal by 7/8/13 — otherwise this repeats C1 one phase later. Related and still open:
**M1** (exception/superseded conflated with `assessed-compliant`) is a **Phase-6-entry decision**,
because the honest fix is a state-machine change; it was deliberately left out of the C1 slice.

*Correction for the record:* the review reads the scope cut as unilateral. It was an explicit,
approved decision — the real gap was that `DIFFERENTIATORS.md`'s gate wasn't amended to match.

**Deferred-table ownership** (authoritative list in `phase-1.md` Group C): `deployments`/`waves`/
`deployment_targets` → Phase 8 · `health_probes` → Phase 9 · `schedules` → Phase 11 ·
`exceptions` → Phase 6 (cross-consumer) · asset provenance/evidence → Phase 4 ·
`advisory_patches` (CVE→KB join) → Phase 5.

### High
| # | Finding | Where it should land | Status |
|---|---------|----------------------|--------|
| H1 | **No authN/authZ anywhere on the roadmap** — tenancy is a caller-supplied `X-Tenant-Id` header; `operators.role`/`external_auth_ref` are never populated | Needs a **new phase** (operator login, tenant claims, RBAC) **before Phase 12** | **OPEN — next decision** |
| H2 | `advisory.schema.json` is closed (`additionalProperties:false`) and cannot carry KEV/EPSS/CVSS provenance; `severity` has no `unknown`; no **patch** schema at all | Phase 1 amend / Phase 5 | closed by C1 slice |
| H3 | **Zero foreign keys** — incl. no `tenant_id → tenants(id)`; permits cross-tenant dangling refs and phantom tenants. Wants composite `(tenant_id, id)` FKs + `UNIQUE (tenant_id, id)` parents | Phase 1 (cheap now) | closed by C1 slice |
| H4 | **No test enforces the RLS convention** on tables later phases add (ENABLE+FORCE+policy+grants); no `ALTER DEFAULT PRIVILEGES` | Phase 1 (`pg_class`/`pg_policies` test) | closed by C1 slice (`RlsConventionTests`) |
| H5 | OpenAPI is an empty skeleton that declares itself **regenerated code-first**, inverting the freeze CLAUDE.md §4.5 defines | Reconcile CLAUDE.md ↔ `api/openapi.yaml` | OPEN |

### Medium / Low (detail in the review)
`M1` exception/superseded conflated with `assessed-compliant` — **Phase-6-entry decision** ·
`M2` no honest failure states once deploy starts (can't record `unreachable` mid-wave) · `M3` one
enum for asset reachability *and* finding lifecycle · `M4` audit can't express system-scope actions
(breaks Phase 2 KEK rotation) + `EfAuditLog` flushes the shared DbContext · `M5` app role can
`DELETE` findings and `data_keys` · `M6` no tenant context off the HTTP path (Hangfire jobs
silently no-op) — *partially defused for Phase 5 by ADR 0010: content sync is tenant-neutral* ·
`M7` single-secret `ResolvedCredential` (no key+sudo password) and unpinned buffer · `M8`
`state`/`kind`/`source` are unconstrained `text` — *done for the new content tables only; the 8
existing tables remain* · `M9` no uniqueness for idempotent upserts — *same: new tables only* ·
`L1`–`L7` as listed.

**Remaining cheap hardening (next slice):** M5, and M8/M9 for the 8 pre-existing tables.

**Note — `audit_log.tenant_id → tenants(id)` is "correct until M4."** The C1 slice adds this FK
because phantom-tenant writes are the larger risk today (H3 + H1). It is **not settled**: M4's
system-scope audit (Phase 2's cross-tenant KEK rotation must be auditable) will make the column
**nullable**, which stays FK-compatible. Phase 2 must not design around it as permanent.

---

## Session Log

Running record of what each session accomplished, so a future session has continuity
without re-explaining. Newest entry first.

### 2026-07-24 — C1 slice, round 3: Debian DSA + full vocabulary sweep
A fresh-session review of the round-2 delta confirmed **no day-one amend for the seven named
Phase-5 feeds**, but flagged one HIGH self-contradiction: round 2 narrowed `advisories.source` to
`(nvd, usn, rhsa, msrc)` while the same commit's ADR 0011 named **Debian DSA** as an applicability
source — and the lab fleet has a Debian 12 box. A Debian advisory had no representable source, so
Phase 5 would hit `ck_advisories_source` on first ingest.

**Fixed:** `dsa` added to `advisories.source`, `patches.source` (mirrors usn), `content_sources.kind`,
`cvss_source`, and both JSON-schema `feed`/source enums. New validated `advisory-dsa.sample.json`
(a real DSA with a `debian:12` fix statement), a DB test that a full DSA advisory + fix statement
inserts cleanly, and `ROADMAP:109`'s Phase 5 connector list now includes Debian DSA so the spec
matches the enum and HARD-PROBLEMS #2/#3.

**Full vocabulary sweep (every Phase-5 feed × every lab distro), so a fourth review finds nothing:**
- Debian 12 → **dsa** (the fix above).
- Rocky 9 / Alma 9 → **decision recorded**: assessed via `rhsa` (the RHEL content they rebuild).
  Native RLSA/ALSA is an *additive* Phase-5/6 option if per-rebuild precision is needed — **not**
  a change to the frozen vocabulary, so no day-one amend either way. (phase-1.md Group B note.)
- `cvss_source`: kept broad (all feeds) **on purpose** — it records which feed *supplied* a score,
  i.e. provenance semantics, not a publisher list. The review's LOW is resolved as intentional.
- Multi-publisher CVE (a `(nvd,CVE-X)` and `(msrc,CVE-X)` row with divergent CVSS): recorded as a
  **Phase 6 correlation** question (which row a finding resolves to), not a Phase 1 constraint.

Ecosystem enum (`deb/rpm/windows`) already covers the whole fleet — no gap. **Tests 53/53 green.**

### 2026-07-24 — C1 slice, round 2: remediation after the fresh-session review
The first commit (`37502b3`) **did not clear** its fresh-session review. Findings and fixes:

**C1 was still literally open.** The first pass amended section *bodies* and missed the
load-bearing sentences: `ROADMAP.md` Phase 1 **exit criteria** still demanded `tenant_id` on every
table (so the phase was graded against a criterion the slice violates), `phase-1.md` **Deliverable
1** contradicted its own Group B, **ADR 0006** still said "every table carries `tenant_id`" with no
amendment note, and `DIFFERENTIATORS.md`'s header and items #1/#3 still said "(Phase 1)" 30 lines
above the new ownership table. All five fixed; ADR 0010 now lists every document it amends, and
ADR 0006 carries an explicit amendment banner.

**Honesty defects in the DDL** (H2 was closed in JSON and reopened in the schema):
- `kev_listed` was `NOT NULL`, collapsing "KEV never synced" into "evaluated, not listed" — the
  exact dishonesty `severity: unknown` was added to fix. **Now nullable and 3-valued.**
- `provenance jsonb NOT NULL` accepts `'[]'`; every test helper was inserting exactly that. **Now
  CHECK-constrained to a non-empty array** — JSON-schema `minItems` can't help, since Phase 5
  writes through EF, not the validator.

**Gaps that would have forced Phase 5 to amend these tables on day one** — which is what pulling
them forward was meant to prevent:
- `content_sources UNIQUE (kind)` capped the deployment at 7 feeds ever. Real feeds are per-stream
  (RHSA per RHEL major, USN per release). **Now `(kind, instance)`**, plus an `endpoint` column so
  an air-gapped mirror has somewhere to live.
- `advisories`/`patches` accepted `kev`/`epss` as publishers. They are **overlays**: one CVE could
  have existed as three rows with divergent scores under `UNIQUE (source, external_id)`, while the
  provenance design assumes one merged row. **Source vocabularies are now split** — advisories
  `nvd/usn/rhsa/msrc`, patches `usn/rhsa/msrc/wsusscn2` — with all seven still valid as provenance.
- Schema fields with nowhere to persist: **added `kev_due_date` (BOD 22-01 deadline),
  `kev_known_ransomware_use`, `cvss_source`, `source_metadata`** — the last being the extension
  point H2's closure rests on.

**The H4 test had a real hole:** it asserted a policy *named* `tenant_isolation` exists but never
counted policies, so `CREATE POLICY debug ON assets USING (true)` — permissive policies OR
together, a total leak — passed. **Now asserts exactly one policy per tenant table**, and
mutation-checked: the `USING (true)` probe fails the test, having passed before. Also added the
missing grant assertions (requirement (b)), which the docs had claimed were covered.

**Tightened:** `content_sources` is no longer readable by `patchmgmt_app` — its `cursor`/
`last_error` are diagnostics that embed internal URLs, and with no RLS every tenant would read
them. `ContentCatalogue.Down()` no longer drops the **cluster-global** `patchmgmt_content` role.
`format` assertion enabled in schema tests (it is annotation-only by default, so every
`date-time`/`uri` was decorative).

**Recorded, not changed:** `RESTRICT` means a tenant with audit rows and an asset with findings
can never be deleted — correct for a compliance product, but Phase 4 and any SaaS offboarding
story must build explicit retire/purge flows. `advisory_affects` holds **fix statements from
applicability sources**; NVD's affected-version *ranges* are out of scope (HARD-PROBLEMS #2
rejects them as an applicability basis) and belong to a Phase-5-owned `advisory_ranges` table —
ADR 0011's original NULL-platform justification wrongly cited NVD and has been corrected. Known
limits now written down: `package_name` on Windows rows, no `arch`, upsert loses prior raw strings.

**Cross-consumer set widened** beyond `exceptions`: `health_probes` (Phase 9, read by 10) and
`schedules` (Phase 11, read by 10) are each owned by a `parallel` phase and read by another
`parallel` phase — the same C1 failure mode. Both must freeze at their owner's start.

**Tests 51/51 green** (19 contracts + 32 integration).

### 2026-07-24 — C1 slice: scope amended + global content catalogue
**Outcome:** **C1 resolved** (option b + partial pull-forward). Also closes **H2, H3, H4**.
Branch `phase-1/c1-content-catalogue`. **Tests 45/45 green** at first commit; see round 2 above.

**Amended (the scope contradiction):** `CLAUDE.md` §4.1 (tenancy rule now names one exemption) ·
`DIFFERENTIATORS.md` (the absolute "every field must exist" gate → a per-differentiator ownership
table + a rule that deferring needs a named owner) · `phase-1.md` (core tables split into Group A
delivered / Group B pulled forward / Group C deferred-with-owner).

**Pulled forward — the global content catalogue (5 tables):** `content_sources`, `advisories`,
`advisory_affects`, `patches`, `patch_supersedence`. **Global: no `tenant_id`, no RLS** (ADR 0010) —
public vendor content, identical per tenant. Isolation is by **role**, not row: `patchmgmt_app`
gets SELECT only; a new `patchmgmt_content` role (non-owner, no BYPASSRLS, guarded idempotent
create) gets SELECT/INSERT/UPDATE and **no DELETE** — content retires via `withdrawn_at`.

**The `advisory_affects` grain (ADR 0011).** The first-draft key `(advisory_id, package_name,
ecosystem)` was **wrong** and would have needed a dedupe migration: one USN fixes `openssl` at a
different version on 20.04/22.04/24.04 — same package, same ecosystem. Fixed by adding a
**`platform`** column (raw as sourced, nullable — NVD CPE records state no platform, and a
sentinel would fabricate content) and keying **`UNIQUE NULLS NOT DISTINCT (advisory_id,
package_name, ecosystem, platform)`**. `NULLS NOT DISTINCT` is load-bearing: without it two
NULL-platform rows both insert and the idempotent upsert silently breaks. `fixed_version` stays
payload, not key. Threaded through migration + entity + JSON schema + sample + 3 behavioural tests.

**H3 — referential integrity:** 12 FKs. `tenant_id → tenants(id)` on all 7 tenant tables (kills
phantom tenants); composite `(tenant_id, asset_id) → assets(tenant_id, id)` on findings and
asset_packages, and `(tenant_id, data_key_id) → data_keys` on credentials (kills cross-tenant
dangling refs — RLS is only a *read* barrier). Content FKs from `findings` are plain single-column
per ADR 0010. RI checks bypass RLS, so these are enforced despite FORCE.

**H4 — `RlsConventionTests`:** every tenant table must have `tenant_id` + ENABLE + FORCE + a
`tenant_isolation` policy with USING *and* WITH CHECK; the global exemption is **asserted**
(no `tenant_id`, no RLS, exact grants per role); and the set of tables lacking `tenant_id` must
equal **exactly** the allowlist — so a 6th global table cannot appear silently. **Mutation-checked:**
a scratch table without `tenant_id` was added to the fixture and both convention tests failed as
intended, then it was removed. Role posture (`rolsuper`/`rolbypassrls` false) asserted for both roles.

**H2 — schemas:** `advisory.schema.json` opened — `severity: unknown`, structured `cvss`
(baseScore/vector/version/source), `kev`, `epss`, **required `provenance[]`**, and `sourceMetadata`
open extension points so Phase 5 can extend *without* a contract change while the known fields stay
closed against typos. New `schemas/patch.schema.json` + sample. Advisory sample now carries two
`platform` rows, so the multi-release case is validated rather than described.

**Gotcha for future sessions:** `RlsTests.SeedAsync` used to guard with `if (Tenants.AnyAsync())`.
The new FK tests create their own tenants in the *shared* fixture DB, so that guard silently
skipped seeding and three tests asserted against an empty database. Guard is now keyed on its own
`TenantA` id. Any new test class that writes to the shared fixture must assume others do too.

**Deliberately NOT in this slice** (left open, see the follow-ups section): H1 (auth/RBAC — still
no owning phase, next decision), H5 (OpenAPI freeze inversion), M1 (exception/superseded conflation
— a Phase-6-entry decision), M5, and M8/M9 for the 8 pre-existing tables. `audit_log.tenant_id →
tenants(id)` is recorded as **"correct until M4."**

**Status:** the `complete*` asterisk on Phase 1 and the 2/3/5 fan-out block stay until this slice
clears a fresh-session review against `docs/reviews/phase-1-review.md`.

**Resume here, in order:**
1. **Fresh-session review** of this slice against `docs/reviews/phase-1-review.md` — does it
   actually close C1/H2/H3/H4? Then drop the asterisk and merge to `main`.
2. **Decide where H1 (authentication/RBAC) lands** — still on no phase, and Phase 12 needs it.
3. Remaining cheap hardening: **M5**, and **M8/M9** for the 8 pre-existing tables.
4. **Then** the Phases 2/3/5 parallel fan-out.

**Environment:** Smart App Control must stay **OFF**; `docker compose up -d` (root);
`dotnet` at `C:\Program Files\dotnet`; apply `db/roles.sql` after `dotnet ef database update` to
provision the dev password for the **new `patchmgmt_content` role**.

### 2026-07-24 (end of session) — superseded by the C1 slice above
Phase 1 merged to `main` at **`fb7b4b5`**, 25/25 tests green, pushed. An independent review then
landed at `docs/reviews/phase-1-review.md` — **1 critical, 5 high, 9 medium, 7 low**.

**The plan recorded at the time** (superseded — C1, H3 and H4 are done; see the entry above):
1. Decide C1 — **done** (option b + partial pull-forward).
2. Cheap hardening: **H3 done**, **H4 done**; **M5**, **M8/M9 on pre-existing tables** still open.
3. Decide where **H1 (authentication/RBAC)** lands — **still open**.
4. Then the Phases 2/3/5 parallel fan-out.

**Environment prerequisites (still current):**
- **Smart App Control must stay OFF** (re-enabling blocks `dotnet run`/`dotnet test` — see below).
- Bring infra up: `docker compose up -d` (root) and `docker compose -f lab/docker-compose.yml up -d` (lab).
- `dotnet` lives at `C:\Program Files\dotnet` (may not be on a stale shell's PATH).

### 2026-07-24 — Phase 1 complete (Contracts)
**Outcome:** Phase 1 (Contracts, solo) complete. **Phases 2 (Vault), 3 (Connector), and 5
(Content) are now parallel-safe** — the first real fan-out (see WORKFLOW.md).

**Built (foundational scope):** a .NET 9 solution (Clean Architecture, modular monorepo):
- `PatchManagement.Contracts` — `EndpointState` + `StateMachine` (11 frozen states,
  transitions-as-data, extensible via `With`, reopenable, no dead-ends); `ICredentialProvider`
  + `ResolvedCredential`; `IAuditLog` + `AuditEntry`; `IModuleRegistrar`.
- `PatchManagement.Persistence` — EF Core 9 + Npgsql; 8 core tables (tenants, operators,
  credentials, data_keys, audit_log, assets, asset_packages, findings); `AppDbContext`;
  `RlsConnectionInterceptor`; `EfAuditLog`; migrations `InitialCreate` + `RlsAndRoles`.
- `PatchManagement.Api` — reflection module discovery (base-dir scan, no shared file);
  `X-Tenant-Id` tenant middleware; `/health` + `/diag/assets`.
- `api/openapi.yaml`; `schemas/{advisory,finding}.schema.json` + samples; `db/roles.sql`;
  `db/schema.sql` (pg_dump export); `.config/dotnet-tools.json` (pins dotnet-ef).

**RLS & requirements (a–d) met:** every tenant table `ENABLE`+`FORCE` RLS + `tenant_isolation`
policy (`NULLIF(current_setting('app.tenant_id',true),'')::uuid` → fail-closed); app connects
as non-owner `patchmgmt_app`, migrations as owner `patchmgmt`; `audit_log` is append-only
(SELECT/INSERT only); module DI convention needs no shared registration file (parallel-safe).

**Tests: 25/25 green** — 19 contracts unit; 6 integration (RLS isolation through the HTTP
pipeline AND at the DbContext as the restricted role; append-only-audit denial; JSON-schema
validation).

**Environment — Smart App Control:** SAC blocked *execution* of freshly-built unsigned binaries
(`0x800711C7`), stopping the app host + integration tests (compilation was fine). **Resolved by
disabling Smart App Control** (dev machine). Keep SAC off for this project (or build/test in
WSL/CI) — re-enabling it will block `dotnet run`/`dotnet test` again.

**Decisions this phase:** foundational schema scope (later phases add their own tables following
the frozen conventions); EF-first migrations with RLS applied via raw SQL; RLS set via
`set_config` on every connection open (leak-safe under pooling, no per-request transaction);
integration tests use an **ephemeral DB on the running compose Postgres** (Testcontainers was
also SAC-blocked). Carry-overs: alpine→Debian(glibc) revert before perf/prod (ADR 0009);
`findings.advisory_id/patch_id` stay FK-less until Phases 5/6.

### 2026-07-24 — Root stack up (Postgres switched to alpine)
**Root product-infra stack is healthy:** `postgres:16-alpine` + `redis:7` both
`healthy` via `docker compose -f docker-compose.yml up -d`. Phase 1's database
prerequisite (migrations + RLS test) is now met.

**Why alpine — and the parity gap (ADR 0009):** Docker Hub's CloudFront CDN
persistently EOF-ed the Debian `postgres:16` image's large layers (~40+ failures this
session; redis and all 5 distro bases pulled fine). Switched the dev image to
`postgres:16-alpine`, which pulls reliably. **Known dev/prod parity gap:** Alpine uses
**musl libc**, Debian uses **glibc** — their collations sort text differently, changing
`ORDER BY` results and **B-tree index ordering** on text keys. **Production must pin the
Debian `postgres:16` (glibc) variant, and dev must be reverted to match before any
performance testing or production packaging.** Do not treat Alpine as the prod baseline.
Tracked in `docs/adr/0009-postgres-alpine-dev-image.md`.

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
- **Postgres CDN issue — RESOLVED** (see the newer log entry above): the Debian
  `postgres:16` image would not pull (CloudFront EOF on large layers). Switched the dev
  image to `postgres:16-alpine` (ADR 0009); root stack now healthy. **Carry-over parity
  gap:** revert dev to Debian `postgres:16` (glibc) — and pin it for prod — before any
  performance testing or production packaging (musl vs glibc collation differences).
- **Git identity** set repo-locally (`HexMystic` / `aiclaude@securelinkme.net`) — no
  global config changed.
- Line-ending note: `.gitattributes` pins `*.sh`/Dockerfiles/`*.yml` to LF (container
  safety); other text files follow the host `core.autocrlf`.

**For the next session (Phase 1 — Contracts, solo):** read `docs/phases/phase-1.md`;
bring the root stack up first (needs Postgres for migrations + the RLS isolation test).
