# Phase 1 Review — Contracts

> Independent review of Phase 1 against CLAUDE.md, ROADMAP.md, phase-1.md,
> HARD-PROBLEMS.md, THREAT-MODEL.md, and DIFFERENTIATORS.md. Findings only — no
> fixes applied. Ordered by severity. Reviewed at commit `fb7b4b5`.

## What holds up

Credit where due, so the findings below land in context: RLS is ENABLE + FORCE
on every table that exists, the policy is fail-closed
(`NULLIF(current_setting(...,true),'')::uuid`), the app role is created plain
(`CREATE ROLE patchmgmt_app LOGIN` — non-owner, non-superuser, no BYPASSRLS),
and the leak tests genuinely run as the restricted role through the real HTTP
pipeline (`tests/PatchManagement.IntegrationTests/RlsTests.cs:20-47`,
`PostgresFixture.cs:23-24`). The state machine is transitions-as-data, no state
is a dead end, closed findings reopen (`verified`/`rolled-back`/`assessed-compliant
→ assessed-missing`), and `audit_log` is INSERT/SELECT-only for the app role with
a test proving UPDATE is denied. `ResolvedCredential.ToString()` is redacted.
Those parts are real.

The problems are in what Phase 1 *didn't* build while calling itself complete,
and in a handful of places where the frozen contract locks in the wrong thing.

---

## CRITICAL

### C1. The schema delivers 8 of the 18 contract tables; the differentiators' required fields mostly do not exist

**Files:** `db/schema.sql` (whole file — tables at lines 39, 58, 80, 97, 116,
132, 155, 172); `docs/phases/phase-1.md:46-66` (the contract table list);
`docs/DIFFERENTIATORS.md:56-58` (the rule being violated);
`docs/ROADMAP.md:220-223` (where the scope cut was self-recorded).

`phase-1.md` lists 18 core tables. The database has 8: `tenants`, `operators`,
`credentials`, `data_keys`, `audit_log`, `assets`, `asset_packages`, `findings`.
Missing entirely:

| Missing table | Which promise dies with it |
|---|---|
| `content_sources` | HARD-PROBLEMS #1 (dual Windows sources need `kind`, `last_sync`, `cursor` for incremental sync); Phase 5 exit criteria |
| `advisories` | Content contract; `findings.advisory_id` (schema.sql:136) points at nothing |
| `advisory_affects` | HARD-PROBLEMS #2 — the `backported` flag and `fixed_version` the backport strategy explicitly requires ("Track `backported` on `advisory_affects`") |
| `patches` | `patches.reversible` and `patches.requires_reboot` — required *now* by DIFFERENTIATORS #1 and #3; `findings.patch_id` (schema.sql:137) points at nothing |
| `patch_supersedence` | HARD-PROBLEMS #4 — the supersedence DAG. No table, no cycle handling, nothing |
| `deployments`, `waves`, `deployment_targets` | DIFFERENTIATORS #3 — "deterministic wave/target modeling … that the simulator can traverse read-only (Phase 1)". The blast-radius dry run has nothing to traverse |
| `health_probes` | DIFFERENTIATORS #1 — "`health_probes` … in Phase 1", verbatim |
| `exceptions` | HARD-PROBLEMS #7 — scope, reason, approver, **expiry**. Phase 6 needs it; nothing carries it |
| `schedules` | DIFFERENTIATORS #3 — the freeze-calendar reference the simulation needs |

Tracing each differentiator through what exists:

1. **Health-probe auto-rollback:** state machine ✓ (`rollback-in-progress`,
   `rolled-back`, `verified → rollback-in-progress` all present,
   `StateMachine.cs:72-83`); `findings.reversible` ✓. But `health_probes` ✗ and
   `patches.reversible` ✗ (no `patches` table).
2. **Unmanaged-asset discovery:** `assets.managed` ✓, `assets.source` ✓
   (schema.sql:65-66). But the promised "provenance/evidence linkage so an
   unmanaged flag is explainable" ✗ — there is no evidence column (e.g.
   `assets.evidence jsonb`) or sighting table. "Seen at IP X by sweep, DHCP
   lease Y, absent from AD" is not representable.
3. **Blast-radius dry run:** ✗ across the board — no `deployments`, `waves`,
   `deployment_targets`, no `requires_reboot`, no freeze calendar.
4. **Explainable risk:** `findings.risk_score` + `findings.risk_explanation
   jsonb` ✓ (schema.sql:140-141). But the content side ✗ — see H2: neither the
   schema nor `advisory.schema.json` can hold KEV membership, EPSS, or CVSS
   provenance, so the explanation's *inputs* have nowhere auditable to live.

DIFFERENTIATORS.md closes with: *"The Phase 1 contract review must confirm
every field above exists before Phase 1 is marked complete — otherwise the
differentiators become expensive retrofits."* That check fails today, yet
ROADMAP.md:20 marks Phase 1 **complete**. The Session Log (ROADMAP.md:221)
records this as a "foundational schema scope" decision — i.e., the frozen
contract's scope was cut unilaterally, which is exactly the class of change
CLAUDE.md NEVER #6 says requires an explicit ask. Either the missing tables get
built before Phase 1 is called complete, or the phase spec and DIFFERENTIATORS
rule get formally amended — but one of the two must happen with the project
owner's sign-off, not in a session log.

Downstream consequence: the deferred tables will now be designed inside
Phases 2–13 (several of them **parallel** sessions), which means the actual
contract gets set later, piecemeal, by whichever session gets there first —
defeating the entire point of a solo contracts phase.

---

## HIGH

### H1. No tenant authentication exists and no phase owns building it

**Files:** `src/Host/Api/Tenancy/HeaderTenantResolver.cs:11-15`;
`src/Host/Api/Program.cs:15`; `docs/ROADMAP.md:14-31` (phase table);
`api/openapi.yaml:50-58`.

The tenant is whatever GUID the caller puts in `X-Tenant-Id`. That is
acknowledged as dev-only ("Replace with an auth-claim resolver before
production" — HeaderTenantResolver.cs:5) — but **no phase in the roadmap
delivers authentication or authorization**. Phases 0–13 cover discovery,
content, deployment, UI, audit; none covers operator login, sessions/tokens,
tenant claims, or RBAC (the `operators` table has `role` and
`external_auth_ref` columns that nothing will ever populate or consume). The
RLS work is genuinely good, but the isolation boundary today is "the caller
promises who they are," and there is no plan line to change that. This is not a
Phase 1 code bug; it is a roadmap hole Phase 1 exposed. Phase 12 (UI) will hit
it first: it cannot ship an operator console with header-selected tenancy.

### H2. The advisory JSON schema cannot carry KEV / EPSS / CVSS provenance — and is frozen shut

**File:** `schemas/advisory.schema.json:7` (`"additionalProperties": false`),
`:24-29` (the only scoring-adjacent fields).

DIFFERENTIATORS #4 requires "content schema retains KEV/EPSS/CVSS provenance
per advisory so inputs are auditable," and Phase 5's exit criteria require
"provenance recorded per record." The frozen schema has: a bare `cvss` number
(no vector, no version), no `kev` flag, no `epss` probability, no `raw_ref` /
provenance object, no per-source ingestion metadata. And because
`additionalProperties` is `false`, Phase 5 cannot even add fields loosely —
every addition is a frozen-contract change. The same closed-schema choice also
means `severity` is a required 5-value enum (line 8, 20-23) with no `unknown`,
so a source that doesn't state severity forces fabrication — the exact
dishonesty HARD-PROBLEMS #8 exists to prevent, applied to content. There is
also no JSON schema for a **patch** record at all (`vendor_id`, `reversible`,
`requires_reboot`, supersedence edges), though phase-1.md deliverable 4 says
"JSON Schemas for content records."

### H3. Zero foreign keys — including no `tenant_id → tenants` and no tenant-consistent references

**Files:** `db/schema.sql:182-250` (constraints section — PKs only);
`src/Infrastructure/Persistence/Migrations/20260723201820_InitialCreate.cs`
(no `ForeignKey` anywhere); `src/Infrastructure/Persistence/Entities/Finding.cs:11-13`.

The Session Log justifies leaving `findings.advisory_id`/`patch_id` FK-less
(their targets don't exist yet — fair). But *nothing* has a foreign key:

- `asset_packages.asset_id` (schema.sql:43) → no FK to `assets`.
- `findings.asset_id` (schema.sql:135) → no FK to `assets`.
- `credentials.data_key_id` (schema.sql:103) → no FK to `data_keys`.
- **No table's `tenant_id` references `tenants(id)`.**

Two concrete failures this permits today:

1. **Cross-tenant dangling references.** RLS stops you *reading* another
   tenant's asset, but nothing stops you *writing* a finding in tenant A whose
   `asset_id` is a tenant-B asset (or a random GUID). A composite FK —
   `FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id)` —
   would make cross-tenant references a constraint violation at the database,
   turning RLS's read-barrier into a full referential barrier. That requires a
   `UNIQUE (tenant_id, id)` on the parent tables — cheap now, painful later.
2. **Phantom tenants.** Combined with H1: an unauthenticated caller can invent
   a fresh GUID, send it as `X-Tenant-Id`, and insert rows "belonging" to a
   tenant that does not exist (RLS `WITH CHECK` passes because the GUC matches
   the row). A `tenant_id → tenants(id)` FK closes this even before auth exists.

### H4. Nothing enforces the RLS convention on tables that don't exist yet — and the whole plan is that later phases add tables

**Files:** `src/Infrastructure/Persistence/Migrations/20260723201850_RlsAndRoles.cs:26-29`
(hard-coded table list); `tests/PatchManagement.IntegrationTests/RlsTests.cs`
(tests one table, `assets`); `docs/ROADMAP.md:220-221`.

The C1 scope cut makes this structural: Phases 2–13 — many parallel — will each
add tables, and each must remember, by convention alone, to (a) add `tenant_id`,
(b) GRANT to `patchmgmt_app`, (c) ENABLE + FORCE RLS, (d) add the
`tenant_isolation` policy. One forgotten `FORCE` in one parallel session is a
silent cross-tenant leak (the table would still *work* — through the owner role
in tests, through grants in the app). Nothing catches it:

- No integration test scans `pg_class`/`pg_policies` asserting every table
  except `tenants` and `__EFMigrationsHistory` has `relrowsecurity` **and**
  `relforcerowsecurity` and a policy. (~20 lines; would freeze the convention
  as an executable contract, which is what Phase 1 was for.)
- No `ALTER DEFAULT PRIVILEGES` — future tables get no grants automatically,
  which at least fails closed, but failure mode is "Phase 5 discovers its
  tables 403 and adds grants by hand," reinventing the pattern each time.

### H5. The "frozen" OpenAPI contract is an empty skeleton that declares itself downstream of the code

**File:** `api/openapi.yaml:5-9` ("this file is regenerated code-first once
controllers exist"); `docs/ROADMAP.md:161-166` (Phase 12 "builds against
OpenAPI").

CLAUDE.md §4.5 lists OpenAPI among the frozen contract artifacts; phase-1.md
deliverable 3 calls it "API surface skeleton." What exists is `/health` plus a
diagnostic endpoint — no resource surface for assets, findings, credentials
(metadata), deployments, or audit. Phase 12's dependency line says it can start
after Phase 1 *because* it builds against the OpenAPI contract; there is no
contract to build against. Worse, the file's own header inverts the freeze:
"regenerated code-first once controllers exist" means the implementation will
dictate the contract, the opposite of what CLAUDE.md §4.5 defines freezing to
mean. One of these documents is wrong, and both are checked in.

---

## MEDIUM

### M1. "Exception" and "superseded" are conflated with "compliant" — in the frozen transition table

**Files:** `src/Shared/Contracts/States/StateMachine.cs:63`
(`AssessedMissing → AssessedCompliant`); `docs/phases/phase-1.md:84`
("`assessed-missing` → `assessed-compliant` (superseded/exception)").

HARD-PROBLEMS #7 requires that an exception "moves a finding out of
'actionable' **without deleting it**" and that "the finding shows *why* it's
suppressed and by whom." HARD-PROBLEMS #8's whole thesis is that states must be
honest. But the only sanctioned path out of `assessed-missing` short of
deploying is `assessed-compliant` — which phase-1.md itself annotates as the
route for both supersedence and exceptions. A risk-accepted, still-vulnerable
host reported as *compliant* is precisely the dishonesty the state model
exists to prevent; a compliance report cannot distinguish "patched," "excepted
until 2026-12-31," and "superseded" when all three read `assessed-compliant`.
The finding row also has no `exception_id` column to carry the "why" (see C1 —
`exceptions` table missing). Phase 6 will be forced to either add states (a
frozen-contract change requiring an ask) or misreport. The enum is documented
as additive-extensible, so the fix is cheap *now*; it stops being cheap once
Phase 6/11/13 have shipped reports against 11 states.

### M2. Once deployment starts, the honest failure states become unreachable

**File:** `src/Shared/Contracts/States/StateMachine.cs:65-83` (outgoing edges of
`DeployInProgress`, `PendingReboot`, `Verified`, `RollbackInProgress`).

`deploy-in-progress` and `pending-reboot` can only go to
`pending-reboot`/`deploy-failed`/`verified`. A host that drops off the network
mid-wave, or never comes back after reboot, cannot be recorded `unreachable` —
the only legal option is `deploy-failed`, which (a) collapses "couldn't
observe" into "failed," the exact conflation HARD-PROBLEMS #8 forbids in the
other direction, and (b) `deploy-failed → rollback-in-progress` is the
rollback trigger edge, so Phase 9 can be steered toward rolling back a host
that merely lost connectivity. Similarly `verified` has no edge to
`unreachable`/`auth-failed`, yet assets share this state column
(EndpointState.cs:4-5): a verified asset that goes off-VPN (HARD-PROBLEMS #10's
roaming case, "known but unreachable") cannot legally re-enter `unreachable`.
Phase 8/9 will hit this in their first real wave.

### M3. One state enum is shared by assets and findings, whose lifecycles diverge

**Files:** `src/Shared/Contracts/States/EndpointState.cs:3-6`;
`db/schema.sql:67` (`assets.state`), `:138` (`findings.state`).

Reachability (an asset property: reachable / auth-failed / unreachable /
last_seen) and patch lifecycle (a finding property: missing / deploying /
verified) are different axes forced through one column. An asset with 40
findings in different deploy states has no meaningful single `state`; Phase 4
(discovery updates asset reachability) and Phase 8 (deployment updates finding
lifecycle) will both write to a shared vocabulary with different intents. The
phase-1.md spec mandates the sharing ("Both **assets** and **findings/targets**
move only along legal transitions," phase-1.md:69), so this is a spec-level
design concern, not an implementation slip — but it should be resolved (e.g.,
a separate small reachability enum for assets) before Phase 4 freezes usage.

### M4. The audit contract cannot record system-scope actions — and its EF implementation flushes strangers' changes

**Files:** `src/Shared/Contracts/Auditing/AuditEntry.cs:8-14` (`Guid TenantId`,
non-nullable); `20260723201850_RlsAndRoles.cs:66-68` (audit RLS `WITH CHECK`);
`src/Infrastructure/Persistence/Auditing/EfAuditLog.cs:24`.

Two problems:

1. Every audit entry must carry a real tenant whose GUC is currently set —
   `TenantId` is non-nullable and the RLS `WITH CHECK` rejects anything else.
   But Phase 2's **KEK rotation is explicitly cross-tenant** (re-wraps every
   tenant's DEK; THREAT-MODEL "Rotation is cheap"), and it must be audited.
   So must failed logins (no tenant yet), content-source sync (Phase 5,
   tenant-neutral), and role/grant changes. The frozen interface has no
   representation for "the system did X" — Phase 2 hits this in its first
   week.
2. `EfAuditLog.AppendAsync` calls `SaveChangesAsync` on the *shared scoped*
   `AppDbContext`. Any entity modifications tracked in the same request are
   committed as a side effect of writing an audit line — audit-append
   mid-unit-of-work silently flushes half-finished business state. It also
   couples audit durability to the business transaction in whichever way the
   caller didn't intend (sometimes you want the audit row to survive a rolled-
   back operation — "attempted and failed" is auditable — and this design
   can't express that either).

### M5. The app role can DELETE findings and data_keys

**Files:** `20260723201850_RlsAndRoles.cs:26-29,54` (grant loop);
`db/schema.sql:425` (data_keys), `:432` (findings).

HARD-PROBLEMS #7's rejected alternative is literally "Deleting/hiding findings
(no audit, silent risk)" — yet `patchmgmt_app` holds DELETE on `findings`. It
also holds DELETE on `data_keys`: deleting a DEK row (one buggy cascade, one
compromised request) permanently bricks every credential encrypted under it —
an unrecoverable, single-statement destruction of the highest-value asset,
executable by the *restricted* role. The uniform `SELECT, INSERT, UPDATE,
DELETE` grant loop treats all tenant tables alike; findings should lose DELETE
(they close, they don't vanish) and `data_keys` should lose DELETE (they
retire via `retired_at`, which exists for exactly this).

### M6. No tenant-context mechanism exists off the HTTP path — Phases 5 and 11 run on background jobs

**Files:** `src/Host/Api/Tenancy/TenantContextMiddleware.cs:13-17`;
`src/Infrastructure/Persistence/Rls/TenantContextAccessor.cs`;
`src/Infrastructure/Persistence/Rls/RlsConnectionInterceptor.cs:12-14`.

The only writer of `TenantContextAccessor` is HTTP middleware. Hangfire jobs
(Phase 11 schedules, Phase 5 content sync, Phase 8 wave execution) have no
request; a job that opens the DbContext gets an empty GUC and — because the
policy fails closed — sees zero rows and *succeeds*, doing nothing. Fail-closed
is correct, but "scheduled patch wave silently no-ops" is its ugly face. The
contract needs a sanctioned pattern now (e.g., a `ITenantScopeFactory` that
creates a scope with the accessor pre-set, plus an explicit system/maintenance
story for tenant-neutral work), or three parallel phases will invent three.

### M7. `ResolvedCredential`/`CredentialKind` cannot represent the credentials Phase 3 actually needs

**Files:** `src/Shared/Contracts/Credentials/CredentialRef.cs:14-18`;
`src/Shared/Contracts/Credentials/ResolvedCredential.cs:13-17,29-36`;
`docs/THREAT-MODEL.md:53-55` ("pinned buffer").

- `CredentialKind` has `SshKey` and `WindowsPassword`. Phase 3's SSH connector
  does "`sudo` for privileged ops" (phase-3.md:68) — a key **plus** a sudo
  password, and possibly a key passphrase, is one logical credential with two
  secrets. The frozen shape (one `byte[]` secret, one username) cannot carry
  it; neither can it carry a WinRM client certificate. Enum members are
  addable, but the single-secret record shape is the real constraint.
- THREAT-MODEL promises plaintext "into a **pinned** buffer that is zeroed
  immediately after." `ResolvedCredential` stores a plain managed `byte[]` —
  unpinned, so the GC may copy/compact it before `Array.Clear` runs, leaving
  stray plaintext copies on the heap; and the constructor aliases the caller's
  array rather than copying, so zeroing is only as good as the caller's
  discipline. The frozen contract type structurally can't honor the
  threat-model sentence (needs pinned/POH allocation or `GCHandle` semantics).

### M8. State and enum columns are unconstrained `text` in the database

**Files:** `db/schema.sql:67` (`assets.state`), `:138` (`findings.state`),
`:101` (`credentials.kind`), `:66` (`assets.source`), `:176` (`tenants.status`).

The "illegal transitions throw" guarantee lives only in C#
(`StateMachine.AssertTransition`); the DB accepts any string in `state`. Raw
SQL, a migration, psql, or a future non-.NET consumer can write `'compliant'`
(not a state) and every EF read of that row then throws in
`EndpointStateNames.FromDbValue` (EndpointState.cs:57-60), bricking list
queries. A `CHECK (state IN (...))` per state column — or a Postgres enum —
would make the frozen state vocabulary a *database* contract, which is where
Phase 1 promised the contracts live. Same for `credentials.kind`,
`assets.source`, `tenants.status`.

### M9. No uniqueness constraints where retries create duplicates

**Files:** `db/schema.sql:264` (`ix_assets_tenant_id_hostname` — non-unique);
findings indexes at `:278,:285` (non-unique).

HARD-PROBLEMS #6 makes retries a design assumption. Two concurrent discovery
runs (or one retried) can insert the same host twice — `(tenant_id, hostname)`
is a plain index. Two assessment runs can open duplicate findings for the same
`(tenant_id, asset_id, advisory_id, patch_id)`. Idempotent *writers* need
unique keys to upsert against; the contract provides none. Retrofitting
uniqueness after Phase 4/6 have created real duplicate data means a data-
cleanup migration nobody wants.

---

## LOW

### L1. Any tenant session can enumerate all tenants
`db/schema.sql:446` — `GRANT SELECT ON tenants` with no RLS (by design, it's
the root table). Fine on-prem; in SaaS mode every tenant can read every other
tenant's name and status. A `tenants_self` policy (id = current GUC) would
preserve the app's needs. Worth a decision note before the "SaaS is a config
change" claim is tested.

### L2. Append-only audit is grants-deep only
`20260723201850_RlsAndRoles.cs:63-68`. The owner role can UPDATE/DELETE
`audit_log` freely, and the app role's DELETE denial is untested (only UPDATE
is, `RlsTests.cs:62-64`). Fine for Phase 1; Phase 13's "immutability
guarantees" will need a trigger-based block on the owner path and/or hash
chaining — flagging so it lands in Phase 13's design, not its retrofit.

### L3. `AuditEntry.Detail` is `string?` bound to a `jsonb` column
`AuditEntry.cs:14` vs `AppDbContext.cs:67`. Any caller passing a plain,
non-JSON string ("deleted asset X") gets an opaque `22P02` Postgres error at
save time. The frozen interface invites the mistake; a `JsonDocument`/typed
detail or a documented "must be JSON" contract (with a test) would not.

### L4. `db/schema.sql` is an unverified hand-run snapshot
It's a pg_dump artifact (header, lines 1-8) with no CI/test asserting it
matches the migrations. It *will* drift silently the first time a later phase
adds a migration and forgets to re-dump — and it is nominally a frozen
contract artifact. Also stale: `AppFactory.cs:8-9` comment still says
"Testcontainers database" after the switch to ephemeral databases
(`PostgresFixture.cs:9-13`).

### L5. No test pins the app role's privilege posture
`RlsTests.cs` proves isolation behaviorally but never asserts
`pg_roles.rolsuper = false`, `rolbypassrls = false`, and non-ownership of the
tables for `patchmgmt_app`. One `ALTER ROLE` in a future migration (or a
helpful DBA granting ownership to "fix" a permissions error) silently voids
FORCE RLS — the cheapest possible test would catch it.

### L6. `StateMachine.With` has no composition point
`StateMachine.cs:94-103`. Each module can mint its own extended machine;
nothing defines the *effective* machine when Phase 8 and Phase 9 (parallel)
each add edges. A registry/composition convention (who owns the canonical
extended instance) should be decided before two parallel phases guess
differently.

### L7. `finding.schema.json` under-specifies the risk fields
`schemas/finding.schema.json:32-35`. `riskScore` has `minimum: 0` and no
maximum (CVSS-derived scores presumably cap at 10 or 100 — unstated), and
`riskExplanation` is a free-form object with no required shape, so the
"explainable" contract (weighted inputs, per DIFFERENTIATORS #4) is
structurally unenforced. Phase 7 will define it; better that the frozen
artifact at least names the intended shape.

---

## Answers to the review questions, in brief

1. **Does the schema support the design docs?** No. Four of four
   differentiators are incompletely designed-in (C1); HARD-PROBLEMS #1, #2, #4,
   and #7 have no schema footprint at all. The state-machine half of the
   promises is in good shape; the table half is ~40% delivered.
2. **Is tenant isolation real?** At the database layer, yes — ENABLE + FORCE
   everywhere that tables exist, fail-closed policy, restricted non-owner role,
   leak tests as that role. Above the database, no — tenancy is a client-
   supplied header with no authentication anywhere on the roadmap (H1), and
   the absence of FKs lets writes reference other tenants' rows and
   nonexistent tenants (H3). The convention also has no enforcement mechanism
   for the many tables later phases will add (H4).
3. **Is the state machine extensible?** Mechanically yes (`With`, additive
   enum, no terminal states, closed findings reopen — all tested). But it
   ships two semantic traps: exception/superseded conflated with compliant
   (M1) and no honest failure states after deployment begins (M2), plus one
   shared enum for two different lifecycles (M3).
4. **Frozen vs loose, inverted where?** Frozen that shouldn't be: closed
   (`additionalProperties: false`) content schemas missing known-needed fields
   (H2); a code-first "frozen" OpenAPI (H5); single-secret `ResolvedCredential`
   (M7); non-nullable `AuditEntry.TenantId` (M4). Loose that should be frozen:
   referential integrity (H3), state vocabulary at the DB (M8), idempotency
   keys (M9), findings/data_keys DELETE grants (M5), the RLS-on-every-table
   convention itself (H4).
5. **What do Phases 2/3+ hit first?** Phase 2: system-scope audit for KEK
   rotation (M4), unpinned secret buffer (M7), DELETE on `data_keys` (M5).
   Phase 3: multi-secret credentials for sudo (M7). Phase 4: asset-state
   vs reachability (M3), duplicate assets on retry (M9), missing evidence
   linkage (C1/D2). Phase 5: closed advisory schema (H2), no `content_sources`
   (C1), tenant context in background jobs (M6). Phase 6: no `exceptions`
   table and the compliant-conflation (C1, M1). Phase 8/9: mid-deploy
   unreachability (M2). Phase 12: no API contract and no auth (H5, H1).
