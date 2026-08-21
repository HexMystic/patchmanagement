# ROADMAP — Master Plan

The single source of truth for what gets built, in what order, and what "done"
means. Each session starts here: pick the next phase whose dependencies are met,
do the work to its exit criteria, then update its **Status** (see
`docs/WORKFLOW.md`).

**Status values:** `not-started` · `ready` (dependencies met, not yet started) · `in-progress` ·
`blocked` · `complete`

**Parallelism:** `solo` phases must be the only phase in flight (they touch shared
contracts or are inherently sequential). `parallel` phases can run concurrently in
separate worktrees. **Phase 8 is solo.**

## Phase summary

| # | Phase | Mode | Depends on | Status |
|---|-------|------|-----------|--------|
| 0 | Environment & design | solo | — | **complete** |
| 1 | Contracts | solo | 0 | **complete** |
| 2 | Credential vault | parallel | 1 | **complete** |
| 3 | Endpoint connector | parallel | 1 | **complete** — merged to `main`, **311 green on `main` post-merge**, 0 skipped. Four review passes. **SSH verified against the lab fleet; WinRM written and unit-proven but NEVER run against a Windows host (D-303)** |
| 4 | Discovery & inventory | parallel | 3 | not-started |
| 5 | Content ingestion | parallel | 1 | **in-progress** |
| 6 | Assessment | solo | 4, 5 | not-started |
| 7 | Risk scoring | parallel | 6 | not-started |
| 8 | Deployment engine | **SOLO** | 6 | not-started |
| 9 | Health probes & auto-rollback | parallel | 8 | not-started |
| 10 | Blast-radius dry run | parallel | 6, 8 | not-started |
| 11 | Scheduling, notifications, reporting | parallel | 6 | not-started |
| 12 | UI | parallel | 1, **14** | not-started |
| 13 | Audit, compliance, evidence | parallel | 6 | not-started |
| 14 | Identity & access (authN/authZ) | parallel | 1 | not-started |
| 15 | Key custody & KMS providers | parallel | 2 | not-started |

> **Numbering note.** Phases 14 and 15 are appended to avoid renumber churn, but the number is a
> label, not a build-order rank — order is set by the *Depends on* column. Identity depends only on
> Phase 1, so it can run in the **early parallel band** alongside 2/3/5; it **must complete before
> Phase 12** (the UI cannot ship on a caller-supplied `X-Tenant-Id` header). It resolves review
> finding **H1**. Phase 15 depends on Phase 2 and **must complete before any multi-instance or SaaS
> deployment** — see [ADR 0016](adr/0016-single-process-vault.md).

**Phase 1 is complete** (amended scope — see C1 below). The C1 slice (`37502b3` → `953a2a5` →
`a8aaa0e`) **resolved C1 and closed H2, H3, H4**, and cleared three independent fresh-session
reviews against `docs/reviews/phase-1-review.md` — the last confirming the content vocabulary is
complete for Phase 5's day-one needs. **Phases 2, 3, and 5 are now unblocked** (the first
parallel fan-out; see WORKFLOW.md).

**Still open from the review — tracked, none blocking the 2/3/5 fan-out:** **H1** is now **placed**
as **Phase 14 (Identity & access)** — a prerequisite of Phase 12, not yet built; **H5** (OpenAPI
freeze inversion), **M1** (a Phase-6-entry decision), **M5**, and **M8/M9 for the 8 pre-existing
tables** remain. The cheap M5/M8/M9 hardening can ride alongside the fan-out or as its own slice.

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

## Phase 2 — Credential vault  · parallel · Status: complete
- **Goal:** Envelope-encrypted credential store; the highest-value asset.
- **Dependencies:** Phase 1.
- **Exit criteria** *(amended 2026-07-26 — see [ADR 0016](adr/0016-single-process-vault.md))*:
  `IKeyProvider` with a **software default**; master-KEK → per-tenant DEK → credential
  envelope; **KEK rotation + DEK re-wrap without re-encrypting credentials**;
  decryption in-memory only; enforced never-log / never-return invariants with
  tests proving them; **every credential access logged via the Phase-1 `IAuditLog`
  from day one** (metadata only — never the secret).
  **Moved out:** the opt-in Azure Key Vault / AWS KMS / HashiCorp Vault backends and
  "provider swappable via config" now belong to **Phase 15**. The seam is delivered and
  exercised; the three cloud providers ship as honest stubs that throw. This is a recorded
  scope amendment in the same shape as C1's amendment to Phase 1, not a lowered bar.
- **Owned paths:** `src/Modules/Vault`.
- **Supported deployment shape:** **single process** for the software provider — one host, one key
  file. Multi-instance and SaaS require a KMS backend and are **not supported before Phase 15**
  ([ADR 0016](adr/0016-single-process-vault.md)). ADR 0015's cross-process lock stays as a safety
  net that bounds the damage; it is not a supported topology.
- **Accepted limitations (redaction), recorded not deferred** — [ADR 0012](adr/0012-log-redaction-scope.md).
  The belt covers the **formatted message** and the **exception object when armed**; **four**
  boundaries are accepted: resolve-time secret self-registration is **rejected** (it would retain
  non-zeroable plaintext for the process lifetime, so the belt is inert in production by design);
  **structured log state** is not scrubbed — and it is the channel production sinks actually read;
  log **scope state** is not scrubbed; secret-bearing records must not rely on a generated
  `ToString()`. The last three are enforced by test (`VaultLoggingConventionTests`,
  `StructuredStateChannelTests`), not just documented. **Residual obligation → Phase 3**
  (Connectors): the belt covers vault log categories only, so the NeverLog scan must be
  extended to the connector module.
- **Two criteria dispositioned rather than silently claimed:** **never-return** is *vacuous by
  construction* here (no vault endpoints exist to assert against) and must be **re-asserted at
  Phases 12/14**; **decryption in-memory only** is met in substance — pinned, self-zeroing buffers
  for plaintext and, since re-review H-1, for KEK material too — with the memory-hygiene residue
  recorded as Phase 2 hardening.
- **Detail:** `docs/phases/phase-2.md`. See `docs/THREAT-MODEL.md`.

## Phase 3 — Endpoint connector  · parallel · Status: complete (merged, `main` green at 311)
- **Goal:** `IEndpointConnector` with SSH **and** WinRM implementations. *(As built: the SSH half is
  verified against the lab fleet; the WinRM half is written and unverified — see the status note
  below. The goal is not the achievement.)*
- **Dependencies:** Phase 1.
- **Exit criteria:** Provider-neutral connector (bastion vs direct is config, not
  code); every operation idempotent + time-bounded with `CancellationToken`;
  connection pooling/concurrency limits (the scaling wall); integration tests
  against the lab fleet over SSH.
- **Owned paths:** `src/Modules/Connectors`, plus `src/Shared/Contracts/Connectors`
  ([ADR 0017](adr/0017-connector-contract-surface.md)).
- **Detail:** `docs/phases/phase-3.md`. See `docs/adr/0003-cloud-agnostic-connector.md`.

### Status at the close of the build — SSH verified, WINDOWS NOT

All six exit criteria (a)–(f) are met **for the SSH/Linux path**, each ticked in `phase-3.md` against
the specific test that proves it. Criterion (c) is proven only by `SshFleetTests`, a theory over all
five lab containers against real sshd — no unit stand-in satisfies it.

> **⚠ The Windows path has never run against a Windows host, and this phase does not claim it has.**
> `WinRmConnector`/`HttpWinRmClient` are **written and unverified**. No Windows target exists here and
> the guardrail (ADR 0007) denies every WinRM cmdlet from a dev session, so the path is untestable in
> this repository by construction. The WinRM suite runs against a **scripted HTTP handler**: it proves
> what the client *sends* and how it reacts to what it is *told*, and it found and fixed four real
> transport defects that way. It proves nothing about how a real WinRM server responds. A green WinRM
> suite is a statement about this client, not about WinRM. Real-host verification is **D-303 (Phase 8)**.

**Tests: 311 passing, 0 skipped.** Contracts 19 · Connectors unit 120 · IntegrationTests 38 ·
Vault 80 (unregressed — Phase 3 did not disturb Phase 2) · **Connectors.IntegrationTests 54**.

> **Correction (cold review R2).** This line previously read "267 passing, 0 skipped · Connectors unit
> 86". **That number was never observed and could not have been.**
> `TimeoutTests.The_connectivity_probe_honours_its_configured_budget_rather_than_a_compiled_in_one`
> awaited a signal that its fake could never raise and carried no timeout, so the connector unit
> project **hung instead of finishing** — no run of it has ever produced a total. The project held
> **92** tests at that point, not 86; it holds 113 now that the fix pass has added coverage. The hang
> is fixed and every count above is measured from a completed run.

> **Cold review R3 (third pass) — no criticals.** It re-ran the whole suite and confirmed 304/0-skipped
> was real this time, then broke every guarantee R2's fix pass introduced: the never-log scans (planted
> secrets in `WinRmConnector` and the real `SshNetSessionFactory` — both went red), the governor's
> cancel-mid-acquire unwind (deleting either release goes red), and the red-first claims for the stdin
> and concurrent-transfer fixes (re-run against the pre-fix blobs on the real lab: 3-of-4 and 2-of-3
> red, with the documented controls staying green). All held. **Its 2 mediums and 2 lows are fixed
> below; the count moved 304 → 308.**

**R3 dispositions.**

> **Correction (cold review R4).** M1 below claimed the replacement meant "laundering the secret
> through any number of intermediates is still caught". **That was false, and the phrase has been
> struck from it.** It held only for straight-line local assignment: `SecretFlowScanner` seeds taint
> from assignments, and a method parameter is not an assignment, so extracting one helper —
> `DecodeSecret(byte[] m) => Encoding.UTF8.GetString(m)` — laundered a private key with all 117 tests
> green. R4 built that exploit in the real `SshNetSessionFactory` and confirmed it. See the R4
> dispositions below for what now carries the guarantee.

- **M1 — the no-plaintext-string guarantee only covered one syntactic form.** Splitting
  `Encoding.UTF8.GetString(credential.Secret)` into two statements reintroduced the immortal managed
  string with all 113 tests green. Replaced the statement-scoped pattern with `SecretFlowScanner`,
  which follows the bytes through local assignments to a fixpoint (and through `CopyTo` into a
  buffer). Proven red-first against both forms and a three-hop chain. **The review asked for a behavioural assertion
  instead; that is not achievable and the attempt was measured, not assumed** —
  `NetworkCredential` reports a non-null, non-read-only `SecurePassword` of identical length whichever
  constructor built it, so `Assert.NotNull(SecurePassword)` passes for the defect exactly as it passes
  for the fix. The managed string is created *before* the credential exists, and a string that is
  created and later collected is indistinguishable at runtime from one that never existed.
  `HttpWinRmClientTests` had already recorded this. The old pattern is kept alongside the new one.
- **M2 — `AllowCredentialDelegation` documented delegation it does not perform.** The flag's only
  effect is skipping the double-hop refusal; nothing anywhere configures CredSSP or Kerberos. The
  contract now says so at the property, names the honest-refusal → opaque-failure trade explicitly,
  and points at **D-304**. Doc-only; the delegation itself stays deferred.
- **L1 — the pool closed sessions under active borrowers at shutdown.** `DisposeAsync` waited on each
  entry's gate but never checked `InUse`, and the gate is free while an operation runs — so shutdown
  disposed live transports and the borrower faulted with `ObjectDisposedException`, which
  `SshConnector` excludes from `IsTransportFault` as a caller bug and which therefore escaped untyped
  from a typed-results API. Now "last one out turns off the lights": idle entries are torn down
  immediately, borrowed ones are handed to the returning lease (gate included, or returning it would
  fault on a disposed semaphore by a new route). Fixed rather than deferred because it is small and
  testable, and both halves are mutation-checked. `IsTransportFault` is unchanged — with the race gone,
  an `ObjectDisposedException` really does mean a disposed connector, which is a caller bug.
- **L2 — `_sftp` was non-volatile beside a volatile `_disposed`,** and read on the deliberately
  unsynchronised fast path. Marked `volatile`. No test: the reordering it prevents is unobservable on
  x86/x64, which is the only architecture the lab runs, so any test would pass for the wrong reason —
  it would first matter on an ARM64 host.

> **Cold review R4 (fourth pass) — no criticals. 1 medium and 1 low fixed; 1 low deliberately not
> changed.** It re-ran the whole suite and confirmed 308/0-skipped, then attacked R3's own fixes. Most
> held: the pool-disposal fix and both its halves survived mutation, the `NetworkCredential`
> measurement that justified rejecting a behavioural assertion was independently reproduced and is
> correct, and `AllowCredentialDelegation` was confirmed comment-only against all four usage sites.
> Two did not — **including the #7 guarantee R3 had just rebuilt, which is why the enforcement model
> for it changed rather than the pattern.** **Count 308 → 311.**

**R4 dispositions.**

- **F1 (medium) — the #7 guarantee had a hole the size of an extract-method refactor.** R4 planted a
  real laundering path in `SshNetSessionFactory.ReadPrivateKey` — `var passphrase = DecodeSecret(bytes);`
  with `DecodeSecret(byte[] m) => Encoding.UTF8.GetString(m)` — and **all 117 tests stayed green** while
  a plaintext private key sat in an immortal managed string. `SecretFlowScanner` seeds taint from
  assignments and `CopyTo` only, so a *parameter* is never tainted; lambdas, local functions, extension
  methods, `out` parameters, instance fields and cross-file helpers all walk past it identically (7 of
  10 probed shapes undetected).
  **The fix is a change of enforcement model, not a better analysis.** `SecretMaterialisationScanner`
  ignores the data entirely and restricts the *capability*: it enumerates every call in the connector
  surface that can turn bytes or chars into managed text — there are exactly **four** — and the test
  pins each to a written justification. A fifth is red by default, whichever helper, lambda or field fed
  it, because the shape is irrelevant to it. Fail-closed where the old check was fail-open. Red-first
  against R4's exploit verbatim (red at the exact line, with both flow checks staying green, which is
  the point), green after; mutation-guarded — blinding the scanner turns two tests red, including a
  stale-allow-list assertion that catches the "scan matches nothing" failure this module shipped twice.
  `SecretFlowScanner` is **retained behind it** for the one case the ban cannot see: a secret reaching
  one of the four calls that *are* allowed. The scan also now covers
  `src/Shared/Contracts/Credentials`, which holds `ResolvedCredential` and was outside every previous
  scan.
  **Behavioural enforcement was built and measured, not dismissed** — see HARD-PROBLEMS §13. It cannot
  work here: SSH.NET leaves 4 managed copies of every key it parses, `NetworkCredential.Password`
  creates another, and `SecureString.AppendChar` decrypts to append so even the correct first-party path
  leaves up to 3 transient copies — nondeterministically (1 run in 5 showed them; 4 showed none).
- **F2 (low/medium) — `EvictIdle`'s `_disposed` guard was check-then-act and did not close the race it
  documented.** The evictor read the flag, took an entry, and could be descheduled while `DisposeAsync`
  disposed that entry's gate; `_entries.Clear()` does not help because the evictor already holds the
  reference. R4 reproduced `ObjectDisposedException` from `EvictIdle` in 150-286 randomised iterations;
  the committed repro hits it in ~22. Under the real system timer that callback has no caller, so this
  is process termination at shutdown. **A volatile flag cannot fix this and the flag was already
  volatile** — the fix is mutual exclusion: the evictor holds a lifetime lock across its *whole* sweep,
  so either the sweep completes before disposal sets the flag or it starts after and returns at once.
  Red-first (22 iterations), green across 100,000 verified iterations; mutation-guarded (removing only
  the evictor's lock goes red at 122, and at 379 after the refinement below).
  **The sweep takes ownership under the lock and closes transports outside it.** Naively, the lock
  would be held across `Session.Dispose()` — network I/O that can block — and `AcquireAsync` calls
  `EvictIdle` on its way in, so a slow close would stall every acquire on the pool. Entries are removed
  from `_entries` under the lock (which is what makes the deferred close safe: disposal only ever walks
  `_entries`, so it can never see them) and closed after releasing it.
  **Residual, not fixed here:** `AcquireAsync` still runs a full sweep on every borrow, now under the
  lifetime lock, so acquires serialise on an O(entries) scan. That scan predates this fix; the lock
  makes it serial. The eviction timer already covers quiet pools, so the call from `AcquireAsync` looks
  redundant — but removing it is a behavioural change to eviction timing and outside R4's scope.
  Raised as **D-310, owner Phase 4** (which is where pool load first becomes real).
- **F3 (low) — flow analysis over-reports across methods in a file.** Deliberately **not changed**.
  It is an over-report, which is the safe direction; it no longer carries the guarantee, so the pressure
  to weaken it when it fires is gone; and "fixing" it by scoping taint per method would *remove* real
  coverage, since a secret assigned in one method and used in another is a genuine pattern. What was
  wrong was the documentation, not the behaviour — corrected below.
- **Two false claims corrected, which R4 rightly called the worst part.** `SecretFlowScanner`'s own doc
  argued it "can only report MORE than the truth, whereas an under-report is a guarantee that quietly
  does not hold" — it under-reports, on the most ordinary refactor there is, and a guard whose docs deny
  the exact way it fails stops the next reader looking. M1 above claimed "any number of intermediates";
  true only for straight-line locals. Both struck, with the correction left in place rather than the
  claim quietly deleted.

The 54 fleet tests are **tests that require the lab fleet**, not optional extras. They hard-fail with
an actionable message when the fleet is down rather than skipping, because a silently-skipped fleet
looks exactly like a passing one and would quietly corrupt the count above. Run them with the fleet up
(`docker compose -f lab/docker-compose.yml up -d`, from the main worktree per WORKFLOW §3).

**Notable findings during the build**, each fixed with a red-first test and recorded in its commit:

- **The module could not resolve in the shipped host at all** — connectors registered as singletons
  captured the scoped `ICredentialProvider`. Found by the host-discovery guard, not by reading.
- **Two tenants shared one authenticated SSH session.** The pool keyed on `host:port#credentialId`, so
  isolation held only because credential ids happen to differ per tenant — incidental, not enforced.
  RLS separates tenants in the database; nothing separated them in the connection pool.
- **A rejected credential was reported as a timeout.** The lab's sshd takes ~10.15s to reject a key
  (measured, stock OpenSSH client); a single 15s budget ran out mid-exchange. Reachability and
  authentication are now budgeted separately — unreachable is detected *faster* and auth rejection is
  classified correctly.
- **Host keys were accepted unconditionally** (`e.CanTrust = true`), making every connection
  interceptable. Now configuration, defaulting to refuse; the lab opts in explicitly.
- **WinRM double-hop detection was inert** — `\b-ComputerName` can never match, because a word
  boundary cannot sit between a space and a hyphen. The check HARD-PROBLEMS #9 relies on had never
  fired.
- **WinRM calls went out unauthenticated** whenever an `IHttpClientFactory` was registered: the
  credential was built and then discarded.
- **The WinRM receive loop was unbounded** — it exhausted the process rather than merely hanging.

### Phase 3 deferrals — every one has a named owner and a gate

`DIFFERENTIATORS.md` forbids deferring without a named owner. Each row states what the owner
inherits and what it cannot claim until then.

| ID | Deferred | Owner | Gate — what cannot be claimed until it lands |
|----|----------|-------|----------------------------------------------|
| **D-301** | Persistent verified-host-key (TOFU) store. The *seam* and reject-by-default ship now | **Phase 4** — it belongs with asset persistence | The connector **cannot be pointed at a real fleet**. `AllowUnknownHostKeys` defaults false, so production either refuses to connect or an operator disables verification wholesale. That flag is the gate, deliberately |
| **D-302** | Windows facts collection (`WindowsFactsParser`) | **Phase 8** | Inventory over WinRM returns `Unsupported`, test-enforced. Phase 6 assessment cannot cover Windows hosts |
| **D-303** | **WinRM verification against a real Windows host** | **Phase 8** | **The Windows path is unproven.** Phase 8 inherits an implementation that compiles, has transport-seam coverage, and has never spoken to a Windows machine. It cannot be claimed working — the SOAP envelopes, Negotiate/NTLM, the shell lifecycle and the base64 transfer round-trip are all unobserved. A Windows wave planned on this is planning on untested code |
| **D-304** | **CredSSP / constrained-Kerberos delegation — the double-hop *solution*** | **Phase 8** | Phase 3 only **surfaces** `DoubleHopRequired` instead of hanging, which is its whole obligation under HARD-PROBLEMS #9. Any Phase 8 flow needing a second hop (an SMB payload fetch, an onward session) will be refused, not silently attempted. `AllowCredentialDelegation` currently only *skips the check* — it delegates nothing |
| **D-305** | Redis-backed distributed concurrency tokens | **Phase 11** (scheduling) | The budget is per-process. Multi-instance deployments would each hold a full budget. The `IConnectionGovernor` surface is already scheduler-ready, so this is an implementation, not a redesign |
| **D-306** | Multi-hop (>1) bastion chains | **Phase 4** — topology lives with assets | A two-hop plan is **refused by name**, not silently truncated to the first hop |
| **D-307** | Passphrase-protected private keys; `CredentialKind` expansion | **Phase 15** (key custody) | `new PrivateKeyFile(stream)` is key-only; an encrypted key fails as `ProtocolError` |
| **D-308** | Collapse `Vault.Tests/Support` onto the shared `TestSupport` project | **Phase 15** — the next phase to edit vault tests | Two capturing-logger implementations coexist. Kept out of Phase 3 to hold this phase's diff inside its owned paths |
| **D-310** | `AcquireAsync` runs a full eviction sweep per borrow, now under the pool's lifetime lock | **Phase 4** — where pool load first becomes real | The O(entries) scan predates R4; the lock added to fix the shutdown race makes it serial. The timer already evicts quiet pools, so the call may simply be redundant — but dropping it changes eviction timing, which is outside R4's scope |
| **D-311** | Extend the text-materialisation ban to `src/Modules/Vault` | **Phase 15** — the next phase to edit vault tests | The ban covers the connector surface only. Phase 2 has two materialising calls (username decode; KEK base64 for the key file) — both legitimate, both already documented, neither enforced. Held out of Phase 3: the vault is Phase 2's owned path and `Connectors.Tests` has no vault dependency by design |
| **D-309** | SSH password / keyboard-interactive auth | **Phase 8** | Key-only. The lab is key-only by construction, so this is untested either way |

**Also inherited by Phase 8, and worth stating plainly:** the sudo-password path (`sudo -S`) is proven
only against a fake session. The lab grants `NOPASSWD` sudo with a locked account password, so it
**structurally cannot** exercise it — a green fleet run says nothing about it.

## Phase 4 — Discovery & inventory  · parallel · Status: not-started
- **Goal:** Discover endpoints; build inventory; surface **unmanaged assets**.
- **Dependencies:** Phase 3.
- **Exit criteria:** IP-range sweep; per-host inventory (OS, packages, patch level)
  via connector; unmanaged-asset correlation against AD/DHCP/managed inventory;
  results persisted with tenant scoping.
- **Owned paths:** `src/Modules/Discovery`.
- **Detail:** `docs/phases/phase-4.md`. See `docs/DIFFERENTIATORS.md` (unmanaged assets).

## Phase 5 — Content ingestion  · parallel · Status: in-progress
- **Goal:** Ingest authoritative vuln/patch content.
- **Dependencies:** Phase 1.
- **Exit criteria:** Connectors for NVD, CISA KEV, EPSS, Ubuntu USN, **Debian DSA**, RHSA,
  MSRC, and `wsusscn2.cab`; normalized into the Phase-1 content schema; incremental &
  idempotent refresh; provenance recorded per record.
- **Owned paths:** `src/Modules/Content`, plus `src/Shared/Contracts/Content`
  ([ADR 0018](adr/0018-content-contract-surface.md)), `tests/PatchManagement.Content.Tests` and
  `tests/PatchManagement.Content.IntegrationTests`.
- **Detail:** `docs/phases/phase-5.md`.
- **See:** `docs/HARD-PROBLEMS.md` (wsusscn2.cab vs MSRC CSAF; #2/#3 require Debian DSA).
- **Progress: 7 of 9 exit criteria ticked, and the two that remain are the two that gate shipping.**
  Three slices so far — foundation (module reachability, the *third* occurrence of the
  unreferenced-module defect after the Vault at `a50d9ec` and Phase 3's WIP), two parse slices
  (`nvd`/`kev`/`epss`/`usn` against real captured payloads), and the store slice (criteria c–f
  against real Postgres). What is left:
  - **(a) is 4 of 8 feeds**, and the gap is not "untested" — `dsa`, `rhsa` and `msrc` parse
    **envelopes no server produces**, and `rhsa` is the dangerous one: it returns a JSON array where
    the parser expects an object, so it yields an empty batch, a green status and an advanced
    cursor. A green sync over an empty catalogue. `wsusscn2` has never expanded its cab.
  - **(b) incrementality is unimplemented, not untested.** No connector reads `state.Cursor`;
    NVD pagination truncates to page 1. The cursor's advance-on-success / hold-on-failure half *is*
    proven.
  - **Nothing invokes `ContentSyncService`** — no job, no endpoint. Same shape as the Phase 2
    rotation trigger, and it needs the same decision (owner: Phase 11).
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
- **Also owns the KEK rotation trigger (cold review L4).** Nothing in `src/` references
  `IKekRotationService` except its DI registration, so **the shipped host cannot start a rotation** —
  review C1 fixed the wiring, not the trigger, and [ADR 0014](adr/0014-system-tenancy-scope.md)
  records the absence as deliberate until Hangfire arrives here. Consume `ITenantScopeFactory` rather
  than inventing a sweep (ADR 0014), expect `TenantScopeConventionTests` to require an allowlist
  entry, and note that **Phase 14** gates whatever trigger is exposed.
- **Owned paths:** `src/Modules/Scheduling`, `src/Modules/Reporting`.

## Phase 12 — UI  · parallel · Status: not-started
- **Goal:** Operator console.
- **Dependencies:** Phase 1 (contracts) — builds against OpenAPI; integrates with
  later modules as they land. **Phase 14 (identity)** — the console authenticates
  operators and derives the tenant from their claims, so it cannot start against the
  dev-only header resolver.
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

## Phase 14 — Identity & access (authN/authZ)  · parallel · Status: not-started
- **Goal:** Replace the dev-only `X-Tenant-Id` header with real authentication: operators
  log in, receive a session/token, and the **tenant is derived from their claims** — closing
  review **H1** (today the isolation boundary is "the caller promises who they are").
- **Dependencies:** Phase 1 (the `operators` table with `role`/`external_auth_ref`, and the
  tenant-resolution seam already isolated behind `HeaderTenantResolver`, exist). Independent of
  the Phase 2/3/5 module work — parallel-safe.
- **Why it's needed / who consumes it:** Phase 12 (UI) hard-depends on it. Every phase benefits:
  the header resolver is a known dev-only stand-in.
- **Exit criteria:**
  - Operator authentication (local credential and/or federated via `operators.external_auth_ref`);
    sessions/tokens issued and validated; logout/expiry.
  - A **claims-based tenant resolver** replacing `HeaderTenantResolver` on the request path, wired
    into the same `TenantContextAccessor` seam the RLS interceptor already reads — so RLS is
    unchanged, only the *source* of the tenant id moves from a header to a verified claim.
  - **RBAC** driven by `operators.role`: authorization checks on privileged operations (the
    endpoints that touch credentials, deployments, exceptions).
  - **Assert the resolved credential's tenant against the authenticated one (cold review L1).** Once
    the tenant comes from a verified claim it has a *different source* from the RLS GUC, so
    `credential.TenantId == <authenticated tenant>` becomes a real second check. Today it would catch
    nothing — both values come from the same `TenantContextAccessor` — and
    [ADR 0013](adr/0013-envelope-binding.md) has been corrected to stop implying otherwise.
  - **Gate the rotation trigger** Phase 11 introduces, and the `ITenantScopeFactory` seam that
    `TenantScopeConventionTests` currently fences by convention rather than by authorization.
  - Any new tables (sessions, role assignments, refresh tokens) **follow the frozen tenancy
    convention** — `tenant_id` + ENABLE/FORCE RLS + `tenant_isolation` policy + grants — which
    `RlsConventionTests` (H4) now enforces automatically. Decide up front whether an operator is
    tenant-scoped or a cross-tenant admin; the latter needs an explicit, audited system-scope path
    (see review **M4/M6** — the same "off the HTTP path / system-scope" gap).
  - **Failed logins are audited** via the Phase-1 `IAuditLog` — which needs the **M4 system-scope
    audit** fix (no tenant yet at login time), so M4 should land with or before this phase.
- **Owned paths:** `src/Modules/Identity`, plus the tenant-resolver swap in `src/Host/Api`.
- **Note — dev posture unchanged until this lands:** `HeaderTenantResolver` stays for local/dev and
  the lab; this phase supplies the production resolver. The guardrail (`.claude/`) and lab-only
  constraint are unaffected.
- **Also gates the cross-tenant seam.** `ITenantScopeFactory` is fenced by a convention test
  (`TenantScopeConventionTests`) rather than by authorization; this phase supplies the real gate on
  any rotation/sweep trigger it introduces ([ADR 0014](adr/0014-system-tenancy-scope.md), re-review H-D).

## Phase 15 — Key custody & KMS providers  · parallel · Status: not-started
- **Goal:** Production-grade master-key custody **and rotation correctness**. Build the opt-in KMS
  backends of `IKeyProvider` (ADR 0002) and close the key-custody findings that only bite outside a
  single process — because **production multi-process arrives via a KMS, not by hardening a shared
  key file** ([ADR 0016](adr/0016-single-process-vault.md)). The scope names rotation explicitly
  because the cold review's M2–M5 land here and Phase 2 is now `complete`, so "Phase 2 hardening" is
  a weaker owner than it was; anything that changes what a rotation *reports* belongs to a live phase.
- **Dependencies:** Phase 2 (the `IKeyProvider` seam, `IKekSource`, rotation and convergence exist
  and are exercised).
- **Why it exists:** Phase 2 ships correct for **one process**. Every finding below is real
  engineering aimed at a deployment shape the product does not have yet, and each would be answered
  by a KMS rather than by us. Parking them in the "Phase 2 hardening" bucket would have satisfied
  `DIFFERENTIATORS.md`'s named-owner rule only nominally — the ROADMAP already calls that bucket a
  naming dodge. **No multi-instance or SaaS deployment is supported until this phase completes.**
- **Exit criteria:**
  - **The three KMS backends implemented** — Azure Key Vault, AWS KMS, HashiCorp Vault — with
    `KeyBinding` mapped onto each backend's own mechanism (`EncryptionContext`, Transit `context`),
    and **Azure's missing `wrapKey` binding parameter solved rather than silently dropped**
    ([ADR 0013](adr/0013-envelope-binding.md)). Inherits Phase 2's **"provider swappable via config
    with no code change to callers"**, with a test that actually sets `VAULT_KEY_PROVIDER`.
  - **H8** — a selected provider is validated at **startup**, not on the first credential operation.
  - **H-2** — the key-file read path works against a **read-only mount** (today every `IKekSource`
    entry point takes a sidecar lock opened `OpenOrCreate`+`ReadWrite`, so it needs *create* access).
  - **H-3** — `FsyncDirectory` cannot fail a rotation that already committed: `DllImport("libc")` can
    throw on **musl**, escaping after `File.Move`, so a durable rotation reports failure and the
    provider keeps its stale cached key. Make the code match ADR 0015's "best-effort" claim.
  - **M-1 — port a cross-process regression test.** Narrower than it once read: the in-process half
    is closed (`ConcurrentRotationTests`), and the cross-process guarantee was **demonstrated** by
    the cold reviewer's eight-process harness on Windows/glibc/musl. What is missing is a test *here*
    that would catch a regression. The in-repo key-file concurrency test still serialises and would
    pass with the sidecar lock deleted, so it does not count.
  - **C-A residual** — cross-process convergence: another process rotating mid-sweep still leaves
    this one on a stale target. Distinct from M-1 (which is now a testing gap, not an unknown).
  - **L3 (MAC over the key file)** — the only part of the old "key file unvalidated on read" item
    still open. Length and base64 validation landed in Phase 2; a MAC is a design question, because
    it needs a key to MAC *with*, which is the custody problem itself. Inherited from "Phase 2
    hardening", a weaker owner now that Phase 2 is `complete`.
  - **Rotation correctness (cold review M2–M5):** a 61-byte ceiling on the pre-auth DEK-unwrap
    allocation (**M2**); `Complete` must not be true for an **empty registry** (**M3**); decide
    whether **retired DEKs** must converge, which is the retirement-floor question (**M4**); and
    **convert the sweep accounting before parallelising it** for the 10,000-endpoint target — the
    counters are plain captured locals and a bare `List<T>`, safe only because one sweep runs at a
    time (**M5**, flagged in the code and in [ADR 0014](adr/0014-system-tenancy-scope.md)).
  - **M-2** — durability under test: `WriteThrough`, `Flush(flushToDisk:true)`, the directory fsync,
    plus lock contention and timeout. Needs a **Linux CI runner** (fsync is a no-op on the Windows
    dev box) and crash injection.
  - **C-A residual** — the convergence window: the target is authoritative at read time but the
    sweep spans many transactions, so another process rotating mid-sweep leaves this one on a stale
    target ([ADR 0014](adr/0014-system-tenancy-scope.md)).
  - **H7** — KEK custody that is not a single point of total loss: a non-ephemeral default path
    (today `AppContext.BaseDirectory/vault/kek.json`), an owned compose volume, and an escrow or
    replication story.
  - **KEK retirement floor** — refuse superseded versions once convergence is *provably* complete,
    so a rotation actually revokes. This is the safe form of what `phase-2.md` wrongly claimed
    rotation already did (re-review H-D2) and is what closes **M-6**'s downgrade-persistence
    residual ([ADR 0013](adr/0013-envelope-binding.md)). It must not strand unconverged DEKs.
- **Owned paths:** `src/Modules/Vault/KeyProviders`, plus the compose/key-volume story for H7.
- **See:** [ADR 0016](adr/0016-single-process-vault.md), [ADR 0002](adr/0002-key-provider.md),
  [ADR 0015](adr/0015-kek-file-durability.md), `docs/THREAT-MODEL.md`.

---

## Phase 1 review — follow-ups

Source: `docs/reviews/phase-1-review.md`, reviewed at commit `fb7b4b5`.
Verdict summary: the RLS work, the state machine, and the append-only audit grants hold up;
the gap is what the frozen contract *didn't* include.

**Status 2026-07-24:** the C1 slice (`37502b3` → `953a2a5` → `a8aaa0e`) closed **C1, H2, H3, H4**
and cleared three fresh-session reviews. **Open:** H1, H5, M1, M5, M8/M9 (pre-existing tables),
L1–L7. None blocks the 2/3/5 fan-out; H1 blocks Phase 12.

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
| H1 | **No authN/authZ anywhere on the roadmap** — tenancy is a caller-supplied `X-Tenant-Id` header; `operators.role`/`external_auth_ref` are never populated | **PLACED** as **Phase 14 — Identity & access** (parallel; depends on 1; prerequisite of 12). Not yet built. | placed 2026-07-24 |
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

## Phase 2 review — follow-ups

Full detail in [`docs/reviews/phase-2-review.md`](reviews/phase-2-review.md) (reviewed at
`305cc81`). IDs below are that document's.

**Status 2026-07-25:** the remediation slice (`a50d9ec` → `ca54bec` → `20b721d` → `e47735f` →
`8dcf349`) closed **C1, C2, C3, C4, H1, H2, H6**, accepted **H3** with the scope corrected and
fenced, and fixed the module-wiring gap that made several findings latent. **Open — tracked, not
fixed:** H4, H5, H7, H8 and the medium cluster. None is a live disclosure path.

**Status 2026-07-26:** the re-review is fully dispositioned (see the re-review section below) and
**H7 and H8 have moved to Phase 15** ([ADR 0016](adr/0016-single-process-vault.md)) — they are key
custody, and Phase 15 owns it. **H4 and H5 remain "Phase 2 hardening"**: they are logging-pipeline
findings, and moving them into a key-custody phase would launder the ownership gap rather than
close it.

### Critical
| # | Finding | Where it should land | Status |
|---|---------|----------------------|--------|
| C1 | **Rotation runs under RLS in production DI and silently rotates nothing** — registered on the app-role context; off the HTTP path the DEK query returns zero rows and it reports success. Same root as `M6` | Phase 2 — sanctioned system tenancy scope ([ADR 0014](adr/0014-system-tenancy-scope.md)) | RESOLVED |
| C2 | Two processes sharing the KEK file overwrite each other's versions — permanent, unrecoverable data loss | Phase 2 — cross-process lock + reload-under-lock ([ADR 0015](adr/0015-kek-file-durability.md)) | RESOLVED |
| C3 | KEK file renamed into place without fsync — a crash can leave a zero-length `kek.json`, losing every credential | Phase 2 — flush-to-disk + atomic rename + directory fsync ([ADR 0015](adr/0015-kek-file-durability.md)) | RESOLVED |
| C4 | A new KEK becomes in-memory `current` before it is durably persisted; no rollback if the save fails | Phase 2 — durable-before-published ([ADR 0015](adr/0015-kek-file-durability.md)) | RESOLVED |

### High
| # | Finding | Where it should land | Status |
|---|---------|----------------------|--------|
| H1 | **No AES-GCM associated data** — an envelope is not bound to its row; cross-tenant relocation decrypts | Phase 2 ([ADR 0013](adr/0013-envelope-binding.md)) | RESOLVED |
| H2 | KEK file created at default permissions, hardened only after writing | Phase 2 — created 0600 via `UnixCreateMode`, closed with [ADR 0015](adr/0015-kek-file-durability.md) | RESOLVED |
| H3 | **Redaction belt scrubs the formatted string only — structured state is forwarded raw** and is what production sinks render | Phase 2 — [ADR 0012](adr/0012-log-redaction-scope.md) amended (decision D); the channel is recorded uncovered and pinned by `StructuredStateChannelTests` | ACCEPTED — documented + fenced |
| H4 | No test can observe the structured channel; the wiring test passes for the wrong reason | **Phase 2 hardening, deferred** — `CapturingLoggerProvider` is formatter-shaped; `StructuredCapturingLoggerProvider` now exists to build on | OPEN |
| H5 | The belt is silently removed by `ClearProviders()` and duplicated by a later `AddConsole()` | **Phase 2 hardening, deferred** — needs an assertion over the real host's provider list | OPEN |
| H6 | Resolve concurrent with rotation races on a non-thread-safe `Dictionary` in `KekKeyset` | Phase 2 — `KekKeyset` made immutable, closed with [ADR 0015](adr/0015-kek-file-durability.md) | RESOLVED |
| H7 | Default KEK path is container-ephemeral — a rebuild destroys the key while the DB keeps the ciphertext | **→ Phase 15** (key custody), which owns the code default *and* the compose volume — the half that previously had no owner at all | OPEN, owned |
| H8 | KMS providers fail at first use, not at startup; the app boots green and throws on the first credential operation | **→ Phase 15**, which builds the providers; a startup probe ships with them | OPEN, owned |

### Medium
Memory hygiene — **Phase 2 hardening, deferred**: orphaned `secretCopy` on the cancel/audit-failure
path; plaintext held across DB round-trips; `Array.Clear` vs `ZeroMemory`; **KEK material held to a
weaker standard than the DEKs it protects**; no page-locking so plaintext is swap- and
coredump-visible · audit gaps — **Phase 13** (the audit-module owner), *gated on the Phase-1 M4
change that makes `AuditEntry.TenantId` nullable*: failed decrypts and `ListAsync` unaudited, audit
written after commit outside any transaction, actor is the constant `"vault"` · correctness —
**Phase 2 hardening, deferred**: no tenant predicate on vault queries; old KEK versions never retired
despite `phase-2.md` (*doc/code mismatch — the code retains them deliberately, which is what makes a
half-finished rotation recoverable; the doc is wrong, not the code*); retired DEKs excluded from
re-wrap; key file unvalidated on read (no length check, no MAC); `NeverReturnContractTests` is
one-assembly/`byte[]`-only/properties-only; EF `EnableSensitiveDataLogging` correct but unpinned by
any test · connector-side never-log residue — **Phase 3**, per [ADR 0012](adr/0012-log-redaction-scope.md)'s
existing hand-off: exceptions escaping the vault are logged by ASP.NET outside the belt's category
scope, and the belt covers vault categories only · ADR 0012 judgements: the scope-state exemption is
*still* justified by a one-directory grep while `IExternalScopeProvider` is process-wide
(**Phase 2 hardening, deferred**), and `RedactedException` being net-negative is **RESOLVED** — it is
now gated on the belt being armed (ADR 0012 decision E) · rotation's `DeksRewrapped` over-reporting —
**RESOLVED** by the C1 slice.

**Recorded because it must not vanish without a verdict — RESOLVED by the C1 + C2/C3/C4 slices.**
The review found rotation was one unbounded transaction across all tenants with no batching or
resumability, and that after ADR 0013 a single poisoned row aborted the whole sweep. This item was
dropped from an earlier version of this paragraph; it is restored with its verdict. Now: the
per-tenant scope is the batch and commit boundary, each DEK re-wraps in its own try/catch, and
`CompleteRotationAsync` converges stragglers without minting a new key
([ADR 0014](adr/0014-system-tenancy-scope.md)).

**New, found while fixing H3 — `KekRotationFailure.Reason` embeds `ex.Message` verbatim.** That
record's members (`TenantId`, `DataKeyId`, `Reason`) miss `VaultLoggingConventionTests`' deliberately
narrow vocabulary, so a future structural log of a `KekRotationResult` would render a provider
exception message raw on the uncovered structured channel. **Phase 2 hardening, deferred.**

**Remaining hardening (deferred):** H4/H5 (belt testability and removability), the memory-hygiene and
correctness mediums, and `KekRotationFailure.Reason`. None is a live disclosure path.
**H7 and H8 moved to Phase 15** on 2026-07-26 — they are key custody, and a phase now owns it.

**Note — no phase owns the logging pipeline or application deployment.** *(Narrowed 2026-07-26: the
key-custody half of this gap is closed — **Phase 15** now owns H7's code default **and** its compose
volume. What remains is logging/telemetry and deployment packaging.)* H3/H4/H5 are logging-pipeline
findings, but Phase 8 "Deployment engine" deploys *patches to endpoints*, and Phase 0 owns
`docker-compose.yml` and is **complete**. Rather than invent a second phase in one slice, these stay
parked as **Phase 2 hardening** — which satisfies `DIFFERENTIATORS.md`'s rule ("deferring **without a
named owner** is not") only because Phase 2 accepts them. Folding them into Phase 15 was considered
and rejected: a key-custody phase is the wrong owner for a logging belt, and putting them there
would launder the gap rather than close it. The gap is real and recurs — ADR 0009's glibc
production-pinning carry-over has the same problem. Naming an owner for logging/telemetry and
deployment packaging is a decision someone still has to make.

### Phase 2 re-review (pre-merge gate) — fully dispositioned 2026-07-26

A fresh-session re-review of the remediated vault at `c557c41` found **2 critical + 9 high**, two of
them regressions the remediation itself introduced. The three merge-blocking ones are fixed:

| # | Finding | Status |
|---|---------|--------|
| CR-1 | **A rotation with the key file absent discarded every KEK version and reported success** — `ReadOrCreateAsync` treated absence as first boot. A regression: removing `SaveAsync` turned the self-healing path into the destruction path | RESOLVED — absence is an error; initialization is opt-in ([ADR 0015](adr/0015-kek-file-durability.md) amendment) |
| C-A | **`CompleteRotationAsync` read the target from a stale cache**, so a non-rotating process could re-wrap the estate back onto a superseded KEK and report `Complete` | RESOLVED — `RefreshCurrentKeyIdAsync` reads under the lock ([ADR 0014](adr/0014-system-tenancy-scope.md) amendment). Window bounded to one sweep, not eliminated |
| H-A | **`Complete` ignored tenant-level failures** — C1's "failed but reported success" one layer up | RESOLVED — `KekRotationResult.TenantFailures`; `Complete` requires both lists empty |

**All eleven re-review findings are now dispositioned (2026-07-26).** The owner decision that
unblocked them: **ship a correct single-process vault; production multi-process arrives via
`IKeyProvider` KMS backends (ADR 0002), not shared-file locking** —
[ADR 0016](adr/0016-single-process-vault.md).

**Fixed on this branch** — real regardless of process count:

| # | Finding | Resolution |
|---|---------|-----------|
| H-1 | **`KekKeyset` was shallow** — constructor, `WithNewVersion()`, `Snapshot()` and `Get()`/`TryGet()` all copied the map and shared the `byte[]`, so a caller held a live reference to key material and a parent keyset aliased its child. `Snapshot()`'s doc claimed the opposite | RESOLVED — the keyset **owns** its material: deep-copied in and out; `Get`/`TryGet` replaced by `Contains` + `CopyKeyTo(keyId, Span<byte>)` writing into a caller-supplied `PinnedBuffer`, so zeroing is structural. The consequence closed was **destruction**, not tampering: a `using` around a resolved KEK would have wiped it process-wide. Proven red-first on all four paths ([ADR 0015](adr/0015-kek-file-durability.md) amendment) |
| H-1 (test) | `VaultLoggingConventionTests` detected records via `<Clone>$`, emitted for record **classes** only — every record struct (e.g. `KeyBinding`) was invisible to a scan ADR 0012 decision C claimed pinned it | RESOLVED — detection also accepts a value type with a compiler-generated `PrintMembers`. **Mutation-checked both ways**: a record-struct probe passed under the old detection and fails under the new. Non-record classes stay out of scope deliberately — they have no generated `ToString()` ([ADR 0012](adr/0012-log-redaction-scope.md)) |
| H-B | **The audit following a committed re-wrap was cancellable.** `EfAuditLog` saves separately, so a cancel between the two writes committed the key change and dropped its only record — no trail exactly when someone is probing the vault | RESOLVED — cancellation checked immediately *before* the save, where stopping is free; the append takes `CancellationToken.None`. Per-DEK cancellation check added (NEVER #5). **Residual:** a *crash* between the writes still loses the row — one transaction needs the M4 `EfAuditLog` change, **→ Phase 13** |
| H-C | **`attempted--` erased a tenant the sweep could not vouch for**, removing it from *both* `TenantsAttempted` and `Failures` — C1 inverted: did something, reported nothing. In shared infrastructure Phases 8/11 are told to consume | RESOLVED — no decrement; the tenant stays counted and is recorded **by name** with the honest verdict (cancelled mid-flight, committed state unknown), so `Complete` is false and the number is explainable ([ADR 0014](adr/0014-system-tenancy-scope.md) amendment) |
| H-D | **"No elevation" held at the database layer, was overstated at the application layer** — `ListTenantsAsync` enumerates the whole registry, and `Create(tenantId)` writes no audit row, so "misuse is attributable" was true only of sweeps | RESOLVED for the claim and the fence: ADR 0014 corrected, and `TenantScopeConventionTests` enforces the seam with an explicit allowlist (mutation-checked). Real authorization is **→ Phase 14**; **auditing `Create` is → Phase 13**, gated on M4. Nothing in the shipped host calls it — no vault endpoints, no rotation trigger |
| H-D1 | `phase-2.md` said "**three** boundaries accepted" and never mentioned the structured-state channel, though ADR 0012 decision D added it — nor decision E (exception replaced only when armed) | RESOLVED — `phase-2.md` and the Phase 2 bullet above now state what the belt covers and list **four** boundaries |
| H-D2 | **Dangerous:** `phase-2.md` said rotation "retires the old version", which the code deliberately does not do. Implementing the doc as written would delete superseded versions and strand every unconverged DEK | RESOLVED — the doc states retention as deliberate, names what depends on it (`CompleteRotationAsync`, crash recovery), and warns explicitly. The safe form — a retirement floor — is **→ Phase 15** |
| M-6 | `key_id` excluded from the DEK binding permits retired-KEK replay | **ASSESSED — exclusion upheld, no code change.** An adversary who writes `wrapped_dek` writes `key_id` in the same statement, so binding over it authenticates a consistently replayed pair; the mismatched pair it would catch already fails on tag mismatch; rotation re-wraps the *same* DEK so replay yields no new plaintext; and changing it is a frozen-contract change (NEVER #6) requiring a re-wrap of every DEK. The genuine residual is **downgrade persistence**, whose fix is the retirement floor — **→ Phase 15**, not a binding change ([ADR 0013](adr/0013-envelope-binding.md)) |

**Deferred — multi-process shared-file hardening; production multi-process arrives via KMS
providers; owner = Phase 15 (Key custody & KMS providers).** Each is recorded with why it is
multi-process-only in [ADR 0016](adr/0016-single-process-vault.md); exit criteria in the Phase 15
section above.

| # | Finding | Why deferred |
|---|---------|-------------|
| H-2 | Every `IKekSource` entry point takes the sidecar lock (`OpenOrCreate`+`ReadWrite`), so a **read-only key mount cannot boot** — it needs *create* access, not merely write | A read-only mounted secret is an orchestrator pattern; a single host owns its key file, and under KMS there is no key file |
| H-3 | `FsyncDirectory`'s `DllImport("libc")` can throw on **musl**, uncaught, escaping *after* `File.Move` committed — a durable rotation reported as failed, provider left on its stale cached key | False *failure*, not false success; recoverable by restart or `CompleteRotationAsync`. ADR 0015's "best-effort" claim corrected to admit the code does not yet match it |
| M-1 | The concurrency test **runs sequentially** and would pass with the sidecar lock deleted; it proves the additive merge, not mutual exclusion | Needs a real second process; no such harness exists (SAC has blocked spawning fresh binaries here). Test comment and ADR 0015 corrected in place |
| M-2 | Nothing tests durability — `WriteThrough`, `Flush(flushToDisk:true)`, directory fsync, lock contention and timeout all unasserted; fsync is a no-op on the Windows dev box | Needs a Linux CI runner and crash injection |
| C-A residual | The sweep spans many transactions, so another process rotating mid-sweep leaves this one converging onto a stale target | Stated in the name — with one process there is no other rotator. Recoverable by re-running |

**Also moved to Phase 15** as the same subject: **H7** (container-ephemeral KEK path, no escrow or
replication — its compose-volume half previously had *no* owner), **H8** (KMS providers throw at
first use rather than at startup), and the **KEK retirement floor**.

**H4/H5 deliberately stay as "Phase 2 hardening"** — they are logging-pipeline findings, not key
custody, and folding them into Phase 15 would launder the ownership gap rather than close it. The
standing note above — that **no phase owns the logging pipeline or deployment packaging** — remains
open and is still a decision someone has to make.

**New, found while dispositioning H-D — recorded, not fixed.** `DataKeyService.GetOrCreateActiveAsync`
mints a tenant's **root DEK with no audit row** (`IAuditLog` is not injected at all). A key-custody
event with no trail — same class and same M4/`EfAuditLog` constraint as the `Create` gap above.
**→ Phase 13**, with the rest of the audit cluster.

### Phase 2 cold review (zero-history, key custody) — 2026-07-26

Full detail in [`docs/reviews/phase-2-cold-review.md`](reviews/phase-2-cold-review.md). IDs below are
that document's.

> **Do not renumber.** The review's MEDIUM block starts at **M2** — there is no M1. That is a
> labelling gap, not a missing finding, and other documents already cite these IDs.

An independent reviewer with no history in this codebase examined the key-custody path and
**confirmed the core**: cross-process custody, no version loss, absence-fatal initialization, the H-1
deep copy, envelope relocation failing, no downgrade path, no cross-tenant bypass — verified on
Windows, glibc **and** musl. It then found two must-fix defects and, more usefully, **disproved three
premises this repo's own documents asserted** (the third is in "Claims that do hold", below).

**Fixed before merge** (`a4fd28c` → `8a073a1` → `347d2f2`):

| # | Finding | Resolution |
|---|---------|-----------|
| **H1** | **`Complete` omitted `DeksSkipped`.** `data_keys.wrapped_dek` is nullable, so a DB-write adversary NULLs chosen rows; they are skipped, not converged, and rotation reports `Complete = true`. The operator does not re-run; the adversary restores the rows and **chooses which credentials survive a post-breach rotation** | RESOLVED — every skip is now a named `KekRotationFailure` *and* `Complete` separately requires `DeksSkipped == 0`; each skip logs at Warning. Red-first on the skipped-DEK case specifically |
| **H2** | **Two concurrent in-process rotations re-pin the estate onto a superseded key**, both reporting success. `KekRotationService` is a **singleton** — so this bites the single-process topology ADR 0016 declared supported. **The "multi-process only" premise was FALSE** | RESOLVED — a rotation gate spanning **mint + sweep** (guarding only the sweep lets both mints land first). Red-first via a forced deterministic interleave, not a timing race ([ADR 0014](adr/0014-system-tenancy-scope.md)) |
| **M6** | `FsyncDirectory` discarded `fsync`'s return, so **`EIO` — the failure it exists to catch — was silent**; and with no `try`/`catch` a throw escaped *after* `File.Move` committed. **The "DllImport throws on musl" premise was FALSE** — the cold review ran it | RESOLVED — guarded body, errno logged via an optional `ILogger`. The ADR 0015 correction asserting the musl premise is retracted there |
| **M7** | `VAULT_SOFTWARE_KEK_INIT` had no one-shot semantics and the refusal told operators to *set* it, so a compose file keeping it set turns **every failed volume mount into a silent fresh-KEK mint** — CR-1 re-armed by its own remedy | RESOLVED — initialization needs the flag **and** an arming sentinel beside the store, which it **consumes**. A lost volume takes the sentinel with it, so the refusal fires on exactly the occasion that matters. Mechanism, not advice |

**Tracked with owners — not fixed:**

| # | Finding | Owner |
|---|---------|-------|
| **M2** | Unbounded pinned pre-auth allocation — `PlaintextLength` sizes a buffer from attacker-influenced bytes before authentication. A wrapped DEK is always 61 bytes, so a ceiling is cheap | **Phase 15** — the bound belongs on the DEK-unwrap path; the credential layer's length is legitimately variable. Not merge-blocking |
| **M3** | An **empty registry yields `Complete = true`** — a sweep over zero tenants reports a successful rotation | **Phase 15**. Same family as H1: a success signal that is true only vacuously |
| **M4** | **Retired DEKs are excluded** from the convergence query and therefore from `Complete` | **Phase 15**. Needs a decision on whether a retired DEK must converge at all, which is the retirement-floor question |
| **M5** | **Sweep accounting corrupts if the sweep is ever parallelized** — plain captured locals, a bare `List<T>`, safe only because one sweep runs at a time. The review's sharper framing: `KekRotationService` documents the *implementation* ("runs tenants sequentially"), while `ITenantScopeFactory.SweepAsync`'s **contract** promises only "once per tenant, each in its own scope" — so the code depends on something the interface never guaranteed | **Phase 15**, and **flagged loudly in the code** at the mutation site and in [ADR 0014](adr/0014-system-tenancy-scope.md), because the person who breaks this will be doing the 10,000-endpoint work and will be reading the sweep, not this table |

**LOW — dispositioned 2026-07-26.** Three of the four are code defects rather than doc points, so
each carries an explicit fix-now-or-defer verdict rather than being swept into Phase 15:

| # | Finding | Owner / verdict |
|---|---------|----------------|
| **L1** | `ResolveAsync` never asserts `credential.TenantId == tenant.TenantId`. The AAD is built entirely from the row, so it authenticates the row **against itself** and contributes zero defense-in-depth if the tenant GUC is ever wrong | **Split, and the doc half is the real one.** Note *why* the assertion is near-useless today: both values come from the same `TenantContextAccessor`, so a wrong GUC makes them wrong **together** and the check still passes. It only acquires meaning once the authorization tenant and the GUC tenant have different sources — i.e. **Phase 14**, which derives the tenant from a verified claim. What is actionable now is that [ADR 0013](adr/0013-envelope-binding.md) overstates the binding as cross-tenant defense-in-depth beyond RLS; **corrected in this slice**. Assertion → **Phase 14**, where it stops being decorative |
| **L2** | `AcquireLockAsync` treats **every** `IOException` as contention, so a wrong path, a permissions problem or a full disk spins the full 30 s and then reports "another process may be rotating" — a misleading diagnosis on the one path where an operator is already under pressure | **FIXED 2026-07-26.** Failures retrying cannot fix (`DirectoryNotFoundException`, `FileNotFoundException`, `PathTooLongException` — all `IOException` **subclasses**, which is why the blanket catch swallowed them) now surface immediately; and the timeout only *claims* contention when the OS actually said so, otherwise naming the real error. Unrecognised `IOException`s are still retried on purpose — misclassifying real contention on a platform we cannot test here would be the worse error |
| **L3** | `ReadFileAsync` validates nothing — no length check on the decoded base64 (a 16-byte KEK loads fine and only fails later at `CopyKeyTo` as an `ArgumentException` about destination size), no MAC over the file | **Length check FIXED 2026-07-26** — the store is validated on read, and a bad key names the version, both lengths and the file. Bad base64 is reported the same way instead of a bare `FormatException`. **MAC over the file → Phase 15** as the design item (it needs a key to MAC *with*, which is the custody question itself) |
| **L4** | **Rotation has no production trigger.** Nothing in `src/` references `IKekRotationService` except the DI registration — C1 fixed the wiring, but nothing in the shipped host can start a rotation | **Phase 11 (Scheduling)** — *not* Phase 15. This is the missing Hangfire schedule, and [ADR 0014](adr/0014-system-tenancy-scope.md) already states the absence is deliberate for now ("real scheduling arrives with Hangfire in Phase 11"). Phase 11 must consume `ITenantScopeFactory` rather than invent its own sweep, and **Phase 14** gates whatever trigger it exposes |

**The third disproven premise — and this one is in our favour.** ADR 0015 called cross-process KEK
custody "argued, not test-proven" and ADR 0016 deferred **M-1** as needing "a harness this repo does
not have". The reviewer **built one**: eight genuine OS processes rotating a single key file
simultaneously — 9/9 versions on disk, no version lost, the seed survived, `current` is one of the
minted versions, every version loadable by a fresh source, and the sidecar lock demonstrably excluded
(a contender waited 3.2 s for a 3 s holder). Identical on Windows, glibc and musl. Their words:
*"This is stronger than the repo believes it is."*

So M-1's grounds change again, and are re-derived rather than left overstated: the guarantee is
**empirically verified on three platforms**, and what the repo still lacks is a **regression test** —
a different and much smaller claim than "untested". Corrected in
[ADR 0015](adr/0015-kek-file-durability.md) and [ADR 0016](adr/0016-single-process-vault.md). Phase 15
should port a harness of this shape rather than re-derive the question.

**A note the next rotation author should read first:** "reports success while untrue" is this
subsystem's characteristic failure — **four instances** (C1, H-A, CR-1/C-A, H1), and the H-A fix
corrected the *numbers* while leaving the dishonesty in `Complete`, where it survived another review.
Every success signal here is guilty until proven. Tabulated in
[ADR 0016](adr/0016-single-process-vault.md), "The recurring hazard", and pointed at from
`KekRotationResult.Complete`.

### Exit criteria — status at the close of Phase 2 (2026-07-26)
Gates completion (CLAUDE.md §6: no phase is done until its exit criteria are met and its tests pass).
The criteria themselves were **amended** on 2026-07-26 — see the Phase 2 section above and
[ADR 0016](adr/0016-single-process-vault.md).

| Criterion | Review verdict at `305cc81` | Now |
|---|---|---|
| Software provider round-trips a credential | Met | **Met** — unchanged |
| KEK rotation re-wraps DEKs without re-encrypting credentials | Algorithm proven; product not (C1) | **Met** — proven off the HTTP path through the real DI container ([ADR 0014](adr/0014-system-tenancy-scope.md)) and over a real key file |
| Decryption in-memory only | Not established | **Met in substance** — plaintext lives in a pinned, self-zeroing `PinnedBuffer`, and since re-review H-1 so does KEK material, with the zeroing made structural rather than remembered. **Residue recorded, not claimed:** the orphaned `secretCopy` on the cancel path, plaintext across DB round-trips, `Array.Clear` vs `ZeroMemory`, no page-locking → **Phase 2 hardening** |
| ~~Provider swappable via config, no caller changes~~ | Not established | **AMENDED OUT → Phase 15.** The seam is delivered and exercised; the three cloud backends ship as honest stubs that throw. Swappability, a test that sets `VAULT_KEY_PROVIDER`, and the startup probe (H8) are Phase 15's exit criteria. Recorded as a scope move in the shape of C1's amendment to Phase 1 — not a lowered bar |
| Never-log **with tests proving it** | Not met | **Met** — proven on the formatted, exception *and* structured channels, with the two unscrubbed channels pinned by convention tests so neither can move silently |
| Never-return **with tests proving it** | Not met | **Vacuous by construction** — there are no vault endpoints to assert against. `NeverReturnContractTests` stands as far as it reaches (`ResolvedCredential` is structurally un-serializable). **Re-assert at Phases 12/14**, when a caller-facing surface first exists |
| Every credential access audited | Partially | **Met for the day-one requirement** — store and resolve audit metadata-only from day one. **Gaps recorded → Phase 13**, all gated on M4: failed decrypts, `ListAsync`, `ITenantScope.Create`, and root-DEK creation |

**Also fixed during review:** `PatchManagement.Api` did not reference `PatchManagement.Vault`, so
the module never loaded in the shipped host — several findings were latent only because of it
(`a50d9ec`).

**M6 — RESOLVED for the tenant-scoped flavour.** C1 was its first concrete casualty: Phase 2
shipped a cross-tenant service straight into the fail-closed hole. The sanctioned pattern now
exists — `ITenantScopeFactory`, cross-tenant work as a sweep of ordinary per-tenant scopes with
RLS still enforced and no elevated role ([ADR 0014](adr/0014-system-tenancy-scope.md)). **Phases 8
(wave execution) and 11 (schedules) should consume it rather than invent their own.** Phase 5 stays
role-based and tenant-neutral per ADR 0010 and does not need it.

---

## Session Log

Running record of what each session accomplished, so a future session has continuity
without re-explaining. Newest entry first.

### 2026-08-21 — Phase 5 DSA CONNECTOR · criterion (a) 6/8 → 7/8 · NOT MERGED

**The last of the three invented envelopes is gone.** `dsa` pointed at `tracker/data/dsa.json`,
which 404s, and parsed a JSON root map Debian serves at no URL. The source was settled by **ADR 0022**
(on `main`; this branch predates the file): salsa's raw plain-text `data/DSA/list`, accepted with its
stability risk named and a fail-loud parser as the binding mitigation. **Only `wsusscn2` (D-504) now
remains.**

**Three open questions were decided, not assumed away.**

1. **Cursor: the newest advisory's FULL id** (`DSA-6455-1`). The file is ordered by DATE, not by id —
   revisions are re-inserted at the top, so 179 DSA numbers carry several revisions and the id order
   **inverts 181 times**. A full id is therefore the only exact resume point: a re-issued old
   advisory appears ABOVE the cursor and is picked up rather than missed. A date cursor is
   day-granular (3 advisories share 2026-08-20) and would force re-ingesting a whole day; a count is
   meaningless against a file that prepends and revises in place. **The cursor is emitted but not
   consumed** — using it to limit parsing is criterion (b), which stays out of scope.
2. **Codename map: all twelve suites in the file, plus the announced `forky`.** The map covered
   `stretch`…`trixie` only, so seven older suites fell through to `debian:<codename>` — **5,240 of
   8,560 suite lines, 61%** of Debian's published history filed off the convention Phase 6 matches
   on. Seven lookup lines fixed it; `forky` (14) was added ahead of its first advisory because the
   platform label is part of row identity and correcting it after an ingest inserts duplicates.
3. **Announcements and annotations: advisory yes, fix statement no.** 217 headers carry no
   `package - description` split at all ("jessie end-of-life"), and 62 suite lines hold an annotation
   where a version belongs. Both become advisories where they have an id, never an affect row —
   `<not-affected>` asserts the OPPOSITE of a fix, and a null-version row would have Phase 6 read a
   fix threshold where Debian said the release was never affected.

**The grammar was measured across the whole 1.1 MB file, and three properties would each have broken
a parser written from July's notes:**

- **Indentation is mixed** — 14,846 tab-indented lines and **525 space-indented**, across 260
  advisories. Anchoring on `	` drops them without erroring.
- **450 pre-2007 ids carry no revision suffix** (`DSA-1209`). A pattern requiring `-N` drops all of them.
- **1,857 advisories span more than one suite** at different versions — the fan-out
  `advisory_affects` is keyed on platform for, and the case a row count cannot catch.

**July's recorded edge-case figures were also wrong**, counted from a partial read: the file has
**6,519** advisories (not 6,466), `<not-affected>` **×55** (not 52) and `<unfixed>` **×3** (not 2).
Corrected in `phase-5.md`.

**Red-first: 20 of 20 red**, every one failing because `JsonDocument.Parse` cannot read plain text —
the wrong-envelope defect itself — then **green at 20**. **The fail-loud guard was mutation-checked**
(`scripts/mutation-guard.ps1`): disabling the throw turned **exactly one** test red and left 19
green, then was reverted and confirmed with `-Absent`.

**The sample is the whole file** (`Samples/PROVENANCE.md`): `dsa.sample.list`, 1,135,558 bytes,
**entire and unedited**. Kept whole deliberately — at ~15× the largest other sample it is a departure,
but the edge cases are scattered through twenty-four years, and a recent-entries subset would contain
only `trixie`, only suffixed ids, only tab indentation and no annotations: the exact shape of a test
that cannot fail.

**Scope held.** `wsusscn2`, criterion (b), `ContentSyncService`, `main` and the other worktrees are
untouched. No frozen contract changed — `dsa` was already in the vocabulary. Content.Tests 99 → 133.

### 2026-08-21 — Phase 5 rhsa + msrc REWRITE · criterion (a) 4/8 → 6/8 · NOT MERGED

**Both connectors were written against envelopes no server produces. Both are now written against
real captured payloads, and both fail loudly rather than returning an empty batch.**

**The formats were investigated fresh, and neither matched what was recorded.** phase-5.md predicted
`rhsa` would need the per-advisory CSAF document (`document.tracking.id` +
`vulnerabilities[].product_status.fixed[]`). The endpoint actually returns a **JSON array of
summaries** carrying `RHSA`, `severity`, `released_on`, `CVEs[]` and `released_packages[]` as NEVRA —
everything the frozen schema needs, in one request. Following `resource_url` per advisory would have
been an N+1 against a vendor API for fields already in hand.

**MSRC was worse, and is the reason "investigate, don't assume" is the rule.** Its endpoint
(`cvrf/v3.0/csaf`) 400s; the real API is `cvrf/v3.0/updates` (a 191-entry monthly index) then one
CVRF document per month. And **the remediation types are not what the CVRF spec's numbering
implies** — measured across the live 2026-Aug document:

| Type | Count | Carries |
|---|---|---|
| 2 | 2198 | the **KB** in `Description.Value`, plus `FixedBuild`, `RestartRequired`, `Supercedence` |
| 3 | 2198 | **no `Description` at all** — a mitigation URL |
| 6 | 354 | a KB article reference, repeating a KB already on Type 2 |

A parser written from the spec reads **Type 3** as "Vendor Fix", finds nothing, and returns an empty
batch that the sync reports as `ok` — the exact defect being fixed, reachable a second time by
following the documentation instead of the data.

**Four traps found in real data that a hand-written fixture would never have contained:**

- `released_packages` is **not uniformly NEVRA** — some advisories list module streams
  (`java-21-openjdk-portable-main@aarch64`) with no version at all. A fix statement without a fixed
  version is not a fix statement, so those are skipped.
- One package at one version on **four arches** is ONE fix statement. `advisory_affects` is unique on
  (advisory, package, ecosystem, platform), so emitting four would have the store keep one and the
  count describe nothing.
- MSRC's `ReleaseDate` is **`0001-01-01T00:00:00` with `ReleaseDateSpecified: false`** — a .NET
  default serialized as a date. Parsed naively it becomes a real timestamp in year 1 that sorts ahead
  of everything and reads as a genuine publication date. Unstated now stays null (HARD-PROBLEMS #8).
- Type 2's `Description` is only **sometimes** a KB. For Visual Studio Code and Teams it is
  `"Release Notes"`, which a trusting parser would mint as a `vendor_id` and then dedupe every such
  product onto. Accepted only when it looks like a KB number.

**Two KBs can fix one product at different builds** (Windows Server 2022 at `…5499` and `…5440` in
one CVE). The unique key cannot hold both, so the **lowest** build is kept: a host that installed
either KB is fixed, and the lower build is the threshold at which that becomes true. Taking the
higher would report patched hosts as vulnerable.

**`requires_reboot` now comes from vendor data** — MSRC's `RestartRequired`, which has three values.
Only an explicit `No` is a statement that no reboot is needed; `Maybe` is treated as true, because a
maintenance window planned as no-reboot that then reboots is the harmful direction.

**Red-first, both connectors.** rhsa: **14 of 16 red** before the rewrite, every failure an assertion
against the real payload ("collection did not contain any matching items" — the empty-batch defect),
green at 16. msrc: **21 of 22 red**, green at 22. **Both fail-loud guards were then mutation-checked**
(`scripts/mutation-guard.ps1`): reverting each throw to a silent `NormalizedBatch.Empty` turned
**exactly one** test red and left the rest green, then was reverted and confirmed with `-Absent`.

**Samples are real captures** (`Samples/PROVENANCE.md`). `rhsa.sample.json` (1,448 B) and
`msrc.updates.sample.json` (48,354 B) are **whole, unedited responses** — `per_page`/`page` are the
API's own paging, so a page is a complete response. `msrc.sample.json` (73,106 B) is **truncated and
declared**: real envelope, four vulnerabilities field-for-field, `ProductTree` filtered to the 33
products they reference, from a live document of 6,428,354 B / 800 vulnerabilities.

**Scope held.** `wsusscn2`, `dsa`, incrementality (criterion b) and `ContentSyncService` are
untouched. **The general zero-count-`ok` hole in `ContentSyncService` remains open for the other six
feeds** — this slice closes it at the connector for `rhsa` and `msrc` only. That is deliberate: a
sync-level guard would flip `ContentSyncServiceTests`' existing assertion that an empty batch is
`ok`, which is out of this slice's scope. Recorded here so it is a known gap, not an oversight.

### 2026-08-16 — Phase 5 STORE SLICE (criteria c–f) · green at 402 · NOT MERGED

**Tests: 374 → 402 passing, 0 skipped, 0 failed**, measured from a completed run of the whole
solution with Postgres and the lab fleet up (Contracts 19 · Content 61 · Connectors unit 120 ·
**Content.IntegrationTests 28** · IntegrationTests 40 · Vault 80 · Connectors.IntegrationTests 54,
~14 min). Vault and Connectors unregressed. `IntegrationTests` still passes at 40, which is the
check that matters for the paragraph below: the host-discovery guard is intact.


**The store's four behavioural criteria are proven against real Postgres, and two real gaps were
found and given owners.** Exit criteria (c) idempotence, (d) provenance merge, (e) overlay safety
and (f) supersedence chains are now ticked in `phase-5.md`, each against a named test —
**7 of 9 criteria ticked**. The two still open are the two that matter most for shipping: **(a)** is
4 of 8 feeds, and **(b)** is half-*built*, not half-tested.

**A third test project had to be created, and the reason is a landmine worth knowing.** The store
criteria need Postgres AND `ContentStore`, and neither existing project can host both:
`Content.Tests` is deliberately infrastructure-free (61 tests, under a second), and
`PatchManagement.IntegrationTests` — which owns `PostgresFixture` — **must never reference the
Content module**. `HostModuleDiscoveryTests` only works because the module's *sole* path into that
project's output is the API's own `ProjectReference`; adding a direct one creates a second path and
the guard silently stops being able to fail (ADR 0018). So the suite lives in a new
`PatchManagement.Content.IntegrationTests`, the same split Phase 3 made for connectors.

**Two gaps found, both pinned by characterization test, neither fixed here** — each belongs to a
later phase and each is now gated rather than merely noted:

- **D-502 — a KEV sync cannot record "evaluated and absent".** `advisories.kev_listed` is
  three-valued by design (NULL = not evaluated, false = evaluated and absent, true = listed) and
  `ContentCatalogueTests` pins that contract — but **the ingestion path can only ever write `true`**.
  After a complete KEV sync every CVE that is not known-exploited is still NULL, indistinguishable
  from a catalogue where KEV never ran. This is precisely the dishonesty HARD-PROBLEMS #8 exists to
  prevent, surviving in the one place nothing was asserting it. **Phase 7 cannot treat NULL as "not
  exploited"** until a sweep marks the complement — which needs a decision about partial and failed
  runs, since a KEV that fetched half its list must not mark the other half absent.
- **D-503 — the supersedence DAG accepts a 2-cycle.** The CHECK and the store's `older.id <> newer.id`
  filter catch a 1-cycle only; A-supersedes-B plus B-supersedes-A inserts cleanly, and an
  effective-head walk does not terminate on it. Deliberately **not** rejected at ingest — a real feed
  can contradict itself and good content must not be refused over it — so **Phase 6's effective-head
  resolution cannot be claimed until it terminates on a cyclic graph**.

**Also proven, without ticking (b):** the cursor advances on success, holds on failure, and is handed
back to the next run; and a record the database refuses rolls back **every record beside it**, so a
failed feed leaves nothing partial behind. (b) stays unticked because no connector ever *sends* a
cursor to a feed — unchanged from slice 2.

**All four guarantees passed first time, so each was shown capable of failing.** Four mutations, each
modelling a mistake an ordinary edit could make rather than blinding the test, each confirmed via
`scripts/mutation-guard.ps1` and reverted the same way. Every one turned **exactly one** test red and
left the other 27 green — so the suite localises a regression rather than merely detecting one:
provenance-merge → overwrite (`Collection: ["nvd"] / Not found: "kev"`); the publisher upsert also
writing `kev_listed`/`epss_score`, which is the exact edit that method's own NOTE warns against;
the two-pass patch/edge loop collapsed into one; and the affects upsert weakened to `DO NOTHING`.

**Not merged, not pushed.** `main` untouched at `614f911`; pushing still needs `--force-with-lease`.

### 2026-07-29 — Phase 5 PARSE SLICE 2 (usn) · green at 374 · NOT MERGED

**USN is parse-tested against real captures, and the Ubuntu codename map was missing the current
LTS.** 349 → **374 passing, 0 skipped, 0 failed** (Contracts 19 · Content **61** · Connectors unit
120 · IntegrationTests 40 · Vault 80 · Connectors.IntegrationTests 54), measured from a completed run
with Postgres and the lab fleet up. Vault and Connectors unregressed.

**The slice is asymmetric on purpose: DSA is NOT in it.** `DebianDsaConnector`'s endpoint 404s, and
probing every plausible alternative established that **Debian publishes no JSON advisory feed at any
URL**:

| Source | Result |
|---|---|
| `tracker/data/dsa.json` *(the connector's endpoint)* · `tracker/data/DSA/list` | **404** |
| `tracker/data/json` | 200, 80 MB, package→CVE→releases — **the string `DSA-` does not appear** |
| `salsa…/security-tracker/raw/master/data/DSA/list` | 200, 1.1 MB, **plain text**, 6,466 advisories |
| `dsa-long.rdf` | 200, but **31 items** and no fixed versions |
| `oval-definitions-*.xml` | **403** |

The connector expects a JSON root map that matches nothing Debian serves — the same invented-envelope
defect already recorded for `rhsa` and `msrc`. Replacing a JSON parser with a text parser, deciding
whether a `salsa.debian.org` raw-git URL is an acceptable production dependency, and handling 6,466
advisories of edge cases is a **data-source decision, not a parse test**, so DSA gets its own slice.
Sourcing Debian from the CVE-keyed JSON was considered and **rejected**: no DSA identifiers means no
`external_id`, breaking the frozen `advisories(source, external_id)` uniqueness and dropping the
advisory-level fixed version HARD-PROBLEMS #2 needs.

**The defect found: the Ubuntu codename map was missing 26.04 LTS.** `DistroReleases.Ubuntu` held
**10** entries and stopped at `oracular` (24.10); Ubuntu's published list has **45**, so **35 were
missing** — `resolute` (26.04 LTS), `plucky`/`questing`/`stonking`, and the interim series
`disco`/`eoan`/`groovy`/`hirsute`/`impish` that the usn-db still ships notices for. Nothing failed,
because the fallback is not lossy — every fix statement for the current LTS was simply filed under
`ubuntu:resolute` instead of `ubuntu:26.04`, off the `ubuntu:<version>` convention Phase 6 matches
assets on. Red-first against real data:

```
Expected: ["ubuntu:22.04", "ubuntu:24.04", "ubuntu:26.04"]
Actual:   ["ubuntu:22.04", "ubuntu:24.04", "ubuntu:resolute"]
```

**Why it had to be fixed now rather than in Phase 6.** `advisory_affects` is unique on
`(advisory_id, package_name, ecosystem, platform)`, so **the label is part of row identity**: once
content has been ingested, correcting a codename makes the next sync INSERT a second row rather than
update the first. Nothing has ingested yet, so this was free today and would have been a data
migration later.

**`UsnConnector` itself needed no change** — the parser was correct as written; the defect was in the
lookup table it consumes. The entire production diff is one file.

**Fixture: 2 notices out of 7,678, from a 339 MB feed.** Both retained complete and unedited,
verified field-identical to the live database. Chosen so a row COUNT cannot stand in for a row VALUE:
`8465-1` ships **one package (`mina2`) across three releases at three different versions**
(jammy/noble/resolute), so counting rows would pass while every version was wrong; `4123-1`
(bionic + disco) is what proved the codename gap. `USN-4147-1` was considered and rejected — a 156 KB
kernel notice, twenty times the whole fixture, covering nothing the other two do not.

**Two branches are unreachable from real data and are left untested rather than faked:** all 7,678
notices carry at least one CVE, so `SourceMetadataJson == null` cannot be exercised; and every
codename in the live database now maps, so the `ubuntu:<codename>` fallback is unreachable too. Both
recorded in `Samples/PROVENANCE.md` — same rule that made slice 1 reject `CVE-2024-3094`.

**Three mutation guards, each confirmed red then reverted:** remove `resolute` → 5 red including the
LTS case by name · remove `disco` → 2 red · neutralise the `USN-` prefixing → 10 red. That third one
matters because it passes first time, so like EPSS in slice 1 it had to be *shown* capable of failing.

**Carried forward:**
- **Criterion (a) is 4 of 8**, named: `nvd`, `kev`, `epss`, `usn`. `dsa`, `rhsa`, `msrc`, `wsusscn2`
  have no parse test, and all three HTTP ones cannot reach their feed.
- **Debian's codename map is deliberately untouched** (`stretch`…`trixie` only; `woody`…`jessie` and
  `forky` unmapped). `DebianPlatform` is called only by the deferred connector, so changing it here
  would be an untested edit. Pinned by `DistroReleasesTests` so the DSA slice inherits a stated
  starting point.
- Unchanged from slice 1: **incrementality is unimplemented** (no connector reads `state.Cursor`),
  NVD pagination truncates to page 1, `wsusscn2` gets no hand-written fixture, and the two standing
  items (**no owner for the logging pipeline or deployment packaging**; **alpine→Debian(glibc)
  Postgres revert, ADR 0009**, before any perf work).

**Not merged, not pushed.** `main` untouched at `614f911`; pushing needs `--force-with-lease`.

### 2026-07-29 — Phase 5 PARSE SLICE 1 (nvd · kev · epss) · green at 349 · NOT MERGED

**Three of eight feeds are now parse-tested against REAL captured payloads.** 322 → **349 passing,
0 skipped, 0 failed** (Contracts 19 · Content **36** · Connectors unit 120 · IntegrationTests 40 ·
Vault 80 · Connectors.IntegrationTests 54), measured from a completed run with Postgres and the lab
fleet up. Vault and Connectors unregressed.

**The fixtures on disk were fabrications, and that was the first thing to fix.** `nvd.sample.json`
and `kev.sample.json` were hand-written **in the same commit as the parsers they fed** — fictional
vendors (`FooCorp`/`libfoo`), fictional CVE ids, and containing *only* the keys each parser reads. A
parser asserted against a fixture written to that parser proves self-consistency and nothing else.
Both deleted and replaced with live captures; `Samples/PROVENANCE.md` records URL, date, size and
selection reasoning for each, and says plainly that a hand-authored payload must never be
reintroduced.

**Two real defects, each proven red-first on real data.**

- **NVD imported a third party's CVSS and labelled it as NVD's.** `ReadCvss` took the first entry in
  a metric family with no preference for who authored it. On `CVE-2024-0182` the leading entry is
  vuldb's — so the advisory recorded **7.3/HIGH where NVD says 9.8/CRITICAL**, a different severity
  band, and then set `CvssSource = "nvd"` regardless. Red-first: `Expected: 9.8 / Actual: 7.3`.
  **This is not an edge case** — a scan of 300 consecutive real CVEs found **125** with a Secondary
  listed first and disagreeing, roughly 40% of the feed.
- **KEV asserted "no ransomware" from a source that said "unknown".** `RansomwareUse` mapped
  `"unknown" => false` two lines below a comment stating the opposite. Red-first:
  `Expected: null / Actual: False`. CISA's "Unknown" means *not confirmed*, not *confirmed absent*;
  recording false lets Phase 7 read absence of evidence as evidence of absence — the same mistake
  the frozen schema already forbids for `kev.listed`.

**The fix was constrained by a frozen contract, which shaped it.** `cvss.source` is
`$ref: #/$defs/feed` and `advisories.cvss_source` is CHECK-constrained to the eight feed names, so a
vendor's own identifier cannot go there. Selection now prefers NVD's own metric; attribution is set
only when NVD really authored it; and the originating party is preserved in `source_metadata`
(`{"cvssOriginator":"product-security@qualcomm.com"}` on `CVE-2023-33025`) so nulling `CvssSource`
stops the lie **without losing the answer** — "who scored this 9.8?" stays answerable (CLAUDE.md §4.6).

**Five mutation guards, all confirmed red then reverted** via `scripts/mutation-guard.ps1`: removing
the Primary/authorship preference · restoring the unconditional `CvssSource = "nvd"` · discarding the
originator · restoring `"unknown" => false` · and removing `JsonHelpers.DoubleOrNull`'s string branch.
That last one matters most: **EPSS passed on the first run**, so its tests had never been seen red.
EPSS sends scores as JSON *strings* (`"0.859740000"`); drop the string branch and `score is null`
sends every record down a `continue` — **7 EPSS tests go red, and in production it would be an empty
batch reported as a successful sync.**

**Three of eight connectors cannot work against their real feeds — found by probing each
`DefaultEndpoint`.** Recorded in `phase-5.md`, each the entry condition for its own slice:

| Feed | Observed | Consequence |
|---|---|---|
| `dsa` | **404** | Debian's live data is CVE-keyed at a different path — a redesign, not a URL swap |
| `msrc` | **400 Invalid ID** | fails loudly |
| **`rhsa`** | **200, but the body is a JSON array** | `Parse` reads `root.Array("advisories")`; `JsonHelpers.Array` returns `[]` for a non-object receiver → **empty batch, `status = 'ok'`, cursor advanced** |

**`rhsa` belongs in this project's recurring-hazard list**: an operator sees a green sync and an empty
catalogue. *Reports success while untrue* — the same class as Phase 2's `Complete` and Phase 3's
checks that could not fire. `rhsa` and `msrc` also parse **invented envelopes** that resemble no real
Red Hat or Microsoft format, so their logic is not merely untested — it is written against a shape no
server produces.

**Also corrected: a false doc claim.** `NvdConnector` said "Incremental via `lastModStartDate`". It
is not. **No connector reads `state.Cursor`** — cursors are computed and persisted but never sent
back to any feed, so refresh is idempotent but **not incremental**. NVD pagination is unimplemented
too (`startIndex`/`totalResults` never read), so a multi-page response is **silently truncated to
page 1** — a second silent-truncation path. Exit criterion (b) stays unticked because the feature is
missing, not merely untested.

**Carried forward:**
- **Five feeds have no parse test** — `usn` (endpoint live, 260 MB, slice 2), `dsa`, `rhsa`, `msrc`,
  `wsusscn2`. Criterion (a) is ticked **3 of 8**, named, not rounded up.
- **`wsusscn2` still has no fixture and must not be given a hand-written one.** The cab is ~627 MB,
  gitignored, absent from this worktree, and its expander has never run. Supersedence inversion is
  the highest-consequence logic in the module; a fabricated `package.xml` would make it look tested.
- **Whether a Rejected CVE should become an advisory is unanswered.** Every no-metrics NVD record in
  the sampled window was Rejected, and `Parse` ingests them regardless of `vulnStatus`. Deliberately
  not settled by a fixture.
- The two standing items are unchanged: **no phase owns the logging pipeline or deployment
  packaging**, and the **alpine→Debian(glibc) Postgres revert (ADR 0009)** is required before any
  perf work or production packaging.

**Not merged, not pushed.** `main` untouched at `614f911`. The branch has diverged from
`origin/phase/5-content` (rebased), so pushing needs `--force-with-lease`.

### 2026-07-28 — Phase 5 FOUNDATION · `phase/5-content` rebased onto `main` · green at 322 · NOT MERGED

**Foundation only. No content-parsing work was done, and none is claimed.** `phase/5-content` was
rebased onto `main` (`614f911`) and taken from "full module, no tests, not in the host" to **322
passing, 0 skipped, 0 failed**, run to completion with Postgres and the lab fleet up.

**Tests: 322** — Contracts 19 · Connectors unit 120 · **IntegrationTests 40** (was 38: +2 discovery
facts) · Vault 80 · Connectors.IntegrationTests 54 · **Content.Tests 9 (new)**. Vault and Connectors
are unregressed, which is not a formality here — the contract move touches the shared Contracts
assembly every module references. Fleet suite ~12m49s; that is slow, not hung.

**The module could not run in the shipped app — the THIRD time this exact defect has shipped.**
`PatchManagement.Api` never referenced `PatchManagement.Content`, so `CompositionRoot`'s
base-directory scan could not find `ContentRegistrar` and all 2,197 lines were unreachable in
production. The Vault did this at `a50d9ec`; Phase 3's WIP did it again; Phase 5's WIP did it a
third time. `HostModuleDiscoveryTests` existed to catch it and had **no Content case** — so nothing
would have noticed while feed-parsing logic was written to green against a dead module.

**Proven red-first, and the red run is the point.** Both new facts failed before the
`ProjectReference` existed — `deps.json` lists no `PatchManagement.Content`, and the real host
container returns an empty `IContentConnector` set — while **the four Vault/Connectors facts stayed
green in the same run**, which is what shows the failure was Content-specific and not a broken
harness. One `ProjectReference` line is the entire delta between red and green.

**Writing the guard required a contract move — [ADR 0018](adr/0018-content-contract-surface.md),
following ADR 0017 exactly.** The behavioural half must assert through a type the integration-test
project already has; referencing the module instead puts its DLL in the TEST output, lets the
base-directory scan succeed on that copy, and makes the guard **incapable of failing** — this
project's characteristic defect. Content had no such type. `IContentConnector`, `ContentSourceState`,
the `Normalized*` records, `ProvenanceEntry`, both overlays, `Feeds` and `Ecosystems` moved to
`src/Shared/Contracts/Content`. `IContentStore`/`IContentConnectionFactory` deliberately did **not**
— they carry `NpgsqlConnection`/`NpgsqlTransaction`, and a database driver in Contracts would make
Phases 6 and 7 inherit Npgsql to read a CVSS score. Two tests pin both halves of that split.

The guard resolves the connector **set**, not the store: `IContentStore` depends on
`ConnectionStrings:Content`, so resolving it would report a *configuration* gap in the language of a
*wiring* gap. The set also asserts all eight feed `Kind`s by name rather than by count — a count
passes for the wrong reason the moment one connector is registered twice.

**Also landed:** `ConnectionStrings:Content` now exists (`appsettings.json`, `.env.example`) — the
`patchmgmt_content` role was in `db/roles.sql` all along but nothing surfaced it, so the module
would have shipped discoverable and unable to write a row, failing only on the first sync via a
deferred throw · `InternalsVisibleTo` on the module csproj, and its odd `9.0.4` pins aligned to the
`9.0.0` house style · **`docs/phases/phase-5.md` written** (phases 1–4 had one; Phase 5 did not,
so there was nothing to read at session start) with **every feed-related exit criterion explicitly
unticked** · `SyncOutcome` moved to `Ingestion/`, the only type the contract move left behind.

**The 9 seed tests are foundation, not parsing.** They pin `Feeds`/`Ecosystems` against the JSON
schema enums — including the asymmetry that KEV/EPSS/wsusscn2 are not advisory publishers and NVD
is not a patch publisher — and they are mutation-checked: adding a ninth feed constant the schemas
do not know about turns 2 red.

**Carried forward honestly — read before trusting Phase 5:**
- **No connector has ever run against its live feed.** All eight are written from published formats
  and unverified against real payloads. A green parse suite would be a statement about the parser,
  not the feed — the same distinction Phase 3 records for WinRM (D-303).
- **`wsusscn2.cab` has never been expanded.** `ExpandCabPackageSource` shells out to Windows
  `expand.exe` and has never seen the real ~627 MB cab; it throws `PlatformNotSupportedException`
  off Windows at *call* time, not startup.
- **Nothing can start a sync.** No Hangfire job, no endpoint, no scheduler — the host discovers the
  module but cannot ingest. Identical in shape to the Phase 2 rotation trigger, whose owner is
  **Phase 11**; this needs the same decision and does not yet have an owner.
- **The vocabulary is still duplicated twice.** `Feeds` is now pinned to the schemas, but
  `AppDbContext`'s CHECK arrays remain an independent copy. Collapsing them changes what a migration
  emits — a frozen-contract question under NEVER #6. Recorded in ADR 0018, **owner Phase 6**.

**Two standing items, restated so they do not get lost — neither is Phase 5 work:**
- **No phase owns the logging pipeline or deployment packaging.** H4/H5 are parked as "Phase 2
  hardening" only because Phase 2 accepts them; Phase 8 deploys *patches to endpoints* and Phase 0
  is complete. Naming an owner for logging/telemetry and deployment packaging is still a decision
  someone has to make (see the standing note in the Phase 2 follow-ups above).
- **The alpine→Debian(glibc) Postgres revert ([ADR 0009](adr/0009-postgres-alpine-dev-image.md)) is
  required before any perf work or production packaging.** Alpine is musl and its libc collation
  differs; Alpine is not the prod baseline.

**For the next session:** the branch is **not merged** and `main` is untouched at `614f911`. The
local branch has diverged from `origin/phase/5-content` (rebased), so pushing needs
`--force-with-lease`. The next slice is the actual content work — start at `docs/phases/phase-5.md`,
where each exit criterion names the test that will prove it.

### 2026-07-28 — Phase 3 cold review R4 + fix pass · **MERGED to `main`** · `main` green at 311

**Phase 3 is complete and merged.** `main` is at the merge commit with **311 passing, 0 skipped, 0
failed**, run to completion with the lab fleet up (Contracts 19 · Connectors unit 120 ·
IntegrationTests 38 · Vault 80 · Connectors.IntegrationTests 54, ~16 min — the fleet suite is slow,
not hung). Both `main` and `phase/3-connector` are pushed.

**R4 found the #7 guarantee was still fail-open — for the third time.** R3 had replaced a
statement-scoped regex with flow analysis; R4 walked past that with one extracted helper
(`DecodeSecret(byte[] m) => Encoding.UTF8.GetString(m)`), laundering a plaintext private key into an
immortal managed string with all 117 tests green. Taint was seeded from assignments, so a **parameter**
was never tainted — and lambdas, local functions, extension methods, `out` params, instance fields and
cross-file helpers all defeated it identically.

**The fix was a change of model, not a better analysis:** stop tracking the data, restrict the
capability. `SecretMaterialisationScanner` enumerates every call in the connector surface that can make
text from bytes — there are exactly four — and pins each to a written justification. A fifth is red by
default whatever shape fed it. The flow scan is kept *behind* it for the one thing the ban cannot see:
a secret reaching one of the four calls that ARE allowed.

**Behavioural enforcement was built and measured before being rejected**, so this question is now closed
with numbers (HARD-PROBLEMS §13): SSH.NET leaves 4 managed copies of every key it parses,
`NetworkCredential.Password` creates another, and `SecureString.AppendChar` decrypts to append — so even
correct first-party code leaves transient UTF-16 copies, **nondeterministically** (1 run in 5). Red for
correct code, red for code we cannot change, and flaky.

**The recurring hazard in this phase is A CHECK THAT CANNOT FIRE** — shipped green three times (the
`-ComputerName` anchor, the statement-scoped regex, the parameter-blind flow analysis). Distinct from
Phase 2's "reports success while untrue". **And twice the documentation denied the exact failure**: the
flow scanner's comment argued it "can only report MORE than the truth" while under-reporting on
extract-method. That sentence is why R3 shipped. Both false claims are struck with the corrections left
visible.

Also fixed: a check-then-act race in the pool's eviction guard (`ObjectDisposedException` on a timer
thread = process termination at shutdown; a volatile flag could not fix it and the flag was already
volatile).

**Carried forward honestly — read before trusting Phase 3:**
- **WinRM has never touched a Windows host.** It is written and unit-proven against a scripted
  transport. A green WinRM suite is a statement about this client, not about WinRM. **D-303, Phase 8.**
- **`AllowCredentialDelegation` delegates nothing** — it only suppresses the double-hop refusal, and now
  says so at the property itself. **D-304, Phase 8.**
- **The materialisation ban does NOT cover the vault.** Phase 2 has two materialising calls (username
  decode; KEK base64 for the key file) — both legitimate, both already documented, neither *enforced*.
  **D-311, Phase 15.**
- **D-310, Phase 4:** `AcquireAsync` runs a full eviction sweep per borrow, now serialised by the
  lifetime lock added for the race fix.
- Deferrals **D-301 … D-311** all carry owners in the Phase 3 deferral table.

**For the next session:** per WORKFLOW §4 step 3, the remaining worktree **`phase/5-content` should be
rebased onto the new `main` and re-tested in isolation** before it lands — that has NOT been done here.

### 2026-07-28 — Phase 3 cold review R2 + fix pass · ~~STILL NOT MERGED~~ (superseded: R3 and R4 followed; merged in the R4 entry above)

A genuinely cold review of `phase/3-connector` (no history of the build) returned **four criticals,
every one verified by execution rather than by reading**, plus five mediums. All are fixed. **`main`
is still untouched and this must not merge yet** — Phase 2 introduced two of its criticals *in the
remediation*, and this remediation is larger than that one was.

**The four criticals.**

1. **The unit suite had never completed.** `TimeoutTests.The_connectivity_probe_honours_its_configured_budget`
   awaited `StallingSshSession.Entered`, but `TestConnectivityAsync` never runs a session operation —
   reaching an authenticated session *is* the proof — so the signal could not fire, and the test had
   no timeout. The project hung rather than failed. **"267 passing, 0 skipped" was therefore a number
   nobody could ever have observed**; the project holds 92 tests, not 86. Fixed with a stalling
   *factory* (a probe spends its time in connect), a boundary walk from both sides, and a `Timeout`
   backstop. Counts corrected in both docs, with the false claim left visible below as the record.
2. **The `sudo -S` path was dead against real SSH.NET.** `SshNetSession.RunAsync` created the input
   stream *before* starting execution; SSH.NET 2025.1.0 refuses that outright. Every elevated command
   carrying a sudo password threw `InvalidOperationException` straight out of the connector, past a
   contract that promises typed results. Invisible because the unit suite stops at
   `RecordingSshSession` and the lab is NOPASSWD, so **no test had ever written a byte to stdin
   through SSH.NET**.
3. **Concurrent transfers over one pooled session corrupted each other.** `EnsureSftpAsync` did
   check→dispose→assign→connect unsynchronised, so a second borrower disposed the SFTP client the
   first was still connecting; both failed and the orphan leaked an authenticated transport. Two
   concurrent pushes to one host is the ordinary shape of a wave. `SessionCapTests` gives every
   operation its own host *by design*, so the pool's central promise was never exercised.
4. **The NeverLog guarantee was enforced by nothing.** Every assertion built an `SshConnector` over a
   stub factory; WinRM and the real SSH factory had no coverage. The reviewer planted a secret in each
   and the whole suite stayed green.

**Mediums:** #5 the governor's cancel-mid-acquire test could not see a leaked permit (the whole unwind
could be deleted and it passed); #6 `IOperationCoordinator` was keyed on the raw idempotency key in a
process-wide singleton, so one tenant could stall another's deployments — the `ConnectionKey` defect,
unfixed one line away; #7 the WinRM password became an immortal managed string; #8 the WinRM probe used
a compiled-in 15s; #9 WinRM had no structural deadline.

**Two lessons worth carrying forward.**

- **Disjoint fake and lab coverage is what let #2 and #3 survive.** Neither was subtle; both sat in a
  seam that one suite stopped short of and the other stepped over. Every fix here is red-first
  *against the real transport*, and the lab suite grew from 44 to 54 facts because of it.
- **A test can pass for reasons unrelated to its name.** #1 hung, #5's mutation survived, and the
  first version of #3's reproduction *passed against the broken code* because the pool's own
  serialisation hid the race. Each fix is mutation-checked with `scripts/mutation-guard.ps1`, which
  refuses to run a suite against source the mutation did not actually land in.

**Tests: Contracts 19 · Connectors unit 113 · IntegrationTests 38 · Vault 80 (unregressed) · fleet 54
= 304, zero skipped.** WinRM remains **written and unverified** — these were transport-seam fixes and
**D-303 (Phase 8) still owns real-host verification**.

### 2026-07-28 — Phase 3 built to green · NOT MERGED · awaiting a COLD review

`phase/3-connector` rebased onto `main` (zero conflicts — the WIP was one purely additive commit) and
brought from "module surface only, no tests, not in the .sln" to **267 passing, 0 skipped**.

**⛔ DO NOT MERGE YET.** `main` is untouched. The next step is **one genuinely cold review** — a fresh
session with **no history of this build**. That is not ceremony: on Phase 2, two of the criticals were
introduced by the remediation itself and were caught only because someone looked again with fresh
eyes, and every review before that had run in the same context as the code. The same context that
wrote this phase must not sign it off.

**Tests: Contracts 19 · Connectors unit 86 · IntegrationTests 38 · Vault 80 · fleet 44 = 267, zero
skipped.** Vault unregressed. The 44 fleet tests **require the lab fleet** and hard-fail (never skip)
when it is down. Verified on freshly built assemblies — see the preflight note below.

> **⛔ THE PARAGRAPH ABOVE IS FALSE — left in place as the record of what was claimed.** The connector
> unit project **hung** and never produced a total (see the 2026-07-28 R2 entry at the top of this log),
> so "267, zero skipped" was never measured. Real figures: Connectors unit **92**, total **273**.

**Commits (10):** `d78b9b7` solution + first compile → `16cca40` test projects + TestSupport →
`716fb56` contract surface to Contracts → `9a4607a` credentials + sudo → `b282d1b` governor +
ConnectionKey (atomic) → `f1c8bcc` TimeProvider deadlines → `88d850c` protocol-keyed resolution +
bastion → `f349dc3` NeverLog scan → `ae09d20` fleet integration → `e520b2b` budget split →
`447e63e` WinRM transport defects.

**⚠ THE WINDOWS PATH HAS NEVER RUN AGAINST A WINDOWS HOST.** WinRM is **written and unverified**. No
Windows target exists here and the guardrail denies every WinRM cmdlet from a dev session, so it is
untestable in this repo by construction. Its suite runs against a scripted HTTP handler — it proves
what the client sends and how it reacts to what it is told, and found four real transport defects that
way. It says nothing about how a real WinRM server responds. **D-303, owner Phase 8.**

**Seven defects that the tests found and reading had not:**
1. The module **could not resolve in the shipped host at all** — singletons capturing the scoped
   `ICredentialProvider`. Found by the host-discovery guard.
2. **Two tenants shared one authenticated SSH session** — the pool key omitted the tenant, so
   isolation was incidental to credential-id uniqueness. RLS separates tenants in the database;
   nothing separated them in the pool.
3. **A rejected credential reported as a timeout** (~10.15s server rejection vs a 15s single budget).
4. **Host keys accepted unconditionally** — every connection interceptable.
5. **Double-hop detection inert** — `\b-ComputerName` cannot match; it had never fired.
6. **WinRM unauthenticated** whenever an `IHttpClientFactory` was registered.
7. **WinRM receive loop unbounded** — exhausts the process, not merely hangs.

**Three recurrences of one tooling hazard, now mechanised.** Scripted patches that silently fail to
match and report success bit three times (a regex revert, a log probe, a diagnostic patch). A run
against unmutated source is indistinguishable from a test that cannot catch the defect.
`scripts/mutation-guard.ps1` now refuses to proceed unless git sees the file modified **and** the
marker is present. Related: `scripts/test-preflight.ps1` fails when a stale `testhost` holds the
output assemblies — that happened once here, and MSBuild reports it as a *warning* under a
"Build succeeded", so a suite ran against code that was not on disk. Both are the build-layer form of
this project's characteristic failure: reporting success while untrue.

**Two tests that passed for the wrong reason, found by mutation, not review.** The WinRM receive-loop
test asserted only that `Timeout` eventually arrived — it passed against the unbounded loop in 95s
instead of 0.5s. The session-cap test measured live sessions, which for a pooling connector counts
every session ever created. Both now assert the property that actually matters (elapsed time; peak
concurrent *operations*). A green test is not evidence until it has been seen red for the right reason.

**For the cold reviewer.** Start at `docs/phases/phase-3.md` — every exit criterion names the test
that proves it. The highest-value targets: the concurrency governor (fairness ordering, waiter
accounting, pruning under cancellation), the credential lifecycle on failure paths, and whether the
NeverLog scans can actually fail. Assume any convention regex is inert until proven otherwise — one
already was.

### 2026-07-26 (merge) — Phase 2 MERGED to main · 135 green on main
**`phase/2-vault` is merged.** `--no-ff` at **`19956af`**, pushed (`42529db..19956af`). 24 commits
plus the merge. **Phase 2 (Credential vault) is `complete`.**

**Verified on `main` itself, not on the branch** — Contracts **19/19**, IntegrationTests **36/36**,
Vault **80/80** = **135**. Host boots from `main`, `/health` 200.

**One conflict, in this file.** `main` carried a session-log entry (`42529db`) committed straight to
it while work continued on the branch, so the branch never had it. Kept, placed in date order below,
and **marked superseded** rather than deleted — it describes tip `7195bee` at Vault 24/24, and its
one pending item was not only applied but later revised (ADR 0012 decision E). Nothing was dropped.

**Every cold-review finding is fixed or deferred with a named owner** — see the cold-review section
above and [`docs/reviews/phase-2-cold-review.md`](reviews/phase-2-cold-review.md). Fixed: H1, H2, M6,
M7, L2, and L3's length check, plus L1's doc half. Deferred with owners: **Phase 15** (KMS backends,
cross-process hardening, KEK escrow, the retirement floor, rotation-correctness M2–M5, L3's MAC) ·
**Phase 13** (the audit cluster, gated on Phase-1 M4) · **Phase 14** (real authorization for the
tenant seam, and L1's assertion once the tenant comes from a claim) · **Phase 11** (the rotation
trigger — nothing in the shipped host can start one).

**NEXT SESSION — a fresh one, and one branch at a time (WORKFLOW §4):** rebase **Phase 3**
(`phase/3-connector`, `67cc648`) onto the new `main`, bring it to green in its own worktree, review,
merge, re-run the suite on `main`; **then** repeat for **Phase 5** (`phase/5-content`, `3a24ccd`).
Both are WIP and **not green today** — Phase 3 has no tests and is not in the `.sln`; Phase 5's test
project is barely started. Neither is crypto, so they warrant a lighter review than Phase 2 — but
Phase 3 consumes `ResolvedCredential` and owns the NeverLog residual that ADR 0012 hands it.

*The entry below was written before the merge; its "held at the merge gate" status is what this
entry closes.*

### 2026-07-26 (later) — cold review actioned · GREEN · then merged (see above)
A **zero-history cold review of the key custody path** — the one the previous entry was holding for —
came back. It **confirmed the core** (cross-process custody, no version loss, absence-fatal init, the
H-1 deep copy, envelope relocation failing, no downgrade, no cross-tenant bypass; verified on
Windows, glibc **and** musl) and found **two must-fix defects plus two false premises**. Commissioning
it was the right call: the false premises were mine, and both were in ADR 0016.

Six commits: `a4fd28c` (H1) → `8a073a1` (H2) → `347d2f2` (M6/M7) → `1d23efa` (ADR 0016 re-derived)
→ `0511bef` (review committed, L1–L4 dispositioned) → this one (L2 + L3 length check).
**Tests: Contracts 19/19, IntegrationTests 36/36, Vault 80/80 — 135 total** (was 121).

**The two premises, both disproven by a reviewer who ran the code:**
- **"Concurrent rotation is multi-process only."** False — `KekRotationService` is a **singleton**, so
  one process is enough. It bit the single-process topology ADR 0016 had just declared *supported*.
- **"`DllImport` throws on musl."** False — they ran it. A three-line fix had been handed to Phase 15
  on a premise nobody verified.

Both fixed rather than re-deferred, and ADR 0016 now says so at the top. The lesson is recorded
there: **a deferral resting on an unverified premise reads as settled, so nobody re-examines it.**

**H1 is the fourth "reports success while untrue" in this subsystem** (C1 → H-A → CR-1/C-A → H1), and
the sequence matters more than the bug: the H-A fix corrected the *numbers* and left the dishonesty
in `Complete`, where it survived another review. Tabulated in ADR 0016 "The recurring hazard" and
pointed at from `KekRotationResult.Complete`, so the next author meets it where they will be standing.

**Red-first proofs, both mandated and both run.** H1: `"a rotation that skipped 1 live DEK(s)
reported Complete"`, failing at the `Complete` assertion itself. H2: two DEKs left on the superseded
`kek-…d81a0912…` while current was `kek-…83480883…`. H2's assertion was corrected after its red run
(a serialised second rotation legitimately supersedes the first), so the **corrected** test was
re-proven red against the unguarded code — the proof covers what was committed, not an earlier draft.

**⛔ STILL NOT MERGED.** `main` untouched at `42529db`. Phases 3/5 not rebased.

**CLOSED — the review is now on disk and every finding is dispositioned.**
[`docs/reviews/phase-2-cold-review.md`](reviews/phase-2-cold-review.md) is committed verbatim, so
every verdict above has a citable source (the re-review never did, which is part of why a cold pass
was needed). It contains **L1–L4** — there is an L4 — and its MEDIUM block starts at **M2**: a
labelling gap, not a missing finding, and deliberately **not** renumbered because other documents
already cite these IDs.

Three of the four LOWs are code defects, so none was swept into Phase 15 by default:
**L1** → the actionable half was a *doc* overstatement in ADR 0013 (the binding authenticates the row
against itself, so it is not defense-in-depth against a wrong tenant context) — **corrected here**;
the assertion goes to **Phase 14**, where it stops being decorative · **L2 and L3's length check were
FIXED** (both cheap, both on the key-custody path; see the LOW table) with only **L3's MAC** deferred
to **Phase 15** as a genuine design item · **L4** (no production rotation trigger) → **Phase 11**,
since it is the missing Hangfire schedule, gated by Phase 14.

**And a third premise fell** — see the cold-review section: cross-process custody is **demonstrated**,
not merely argued. That one made the system look *worse* than it is; the other two made it look
better. Same cause: claims written from reasoning and never executed.

### 2026-07-26 — Phase 2 closed out · GREEN and pushed · HELD AT THE MERGE GATE
**Phase 2 is `complete` and `phase/2-vault` is green — and deliberately NOT merged.** `main` is
untouched at `42529db`. Three commits landed on top of `c132b25`:

1. `32c8716` — **H-1**: the KEK keyset now owns its key material.
2. `493ebf2` — **H-B/H-C/H-D**: cancellation must not make a sweep lie; the cross-tenant seam is fenced.
3. this one — dispositions, ADR 0016, Phase 15, exit-criteria amendment.

**Tests: Vault 66/66 (was 54), IntegrationTests 36/36, Contracts 19/19 — 121 total.** Twelve added.

**⛔ DO NOT MERGE YET.** The owner is deciding whether to commission **one genuinely cold review of
the key-custody path** before it reaches `main`. The reason is specific and still true: of the
criticals found on this branch, **two were introduced by the remediation itself** (CR-1 and C-A) and
were caught only because someone looked again — and every review so far has run in the same session
context as the code. That is not a track record that justifies self-certifying key custody. Do not
merge, do not rebase Phases 3/5, do not touch `main`, until that call is made.

**The decision that unblocked the eight open findings:** ship a correct **single-process** vault;
production multi-process arrives via **`IKeyProvider` KMS backends** (ADR 0002), not by hardening
shared-file locking. Recorded as **[ADR 0016](adr/0016-single-process-vault.md)**. Nothing in the
repo claimed multi-instance, so this narrows a supported shape rather than retracting a promise —
and it puts the multi-process work where it was always going to be solved properly.

**New: Phase 15 — Key custody & KMS providers** (parallel, depends on 2). A real phase rather than
another line in the "Phase 2 hardening" bucket the ROADMAP itself calls a naming dodge. It owns the
three KMS backends, **H-2/H-3/M-1/M-2** and C-A's residual window, plus **H7** (whose compose-volume
half previously had *no* owner) and **H8**, and the **KEK retirement floor**. **No multi-instance or
SaaS deployment is supported until it completes.**

**Fixed, each proven red-first** with the wrong values recorded in its commit body:
- **H-1** — the keyset copied only the *map*; all four accessors shared the `byte[]`. The exposure
  that mattered was destruction, not tampering: `PinnedBuffer.Dispose` zeroes, so an ordinary
  `using` around a resolved KEK would have wiped it for every later wrap in the process. Now
  deep-copied in and out, with `Contains` + `CopyKeyTo(Span<byte>)` replacing `Get`/`TryGet`.
- **H-1 (test)** — `VaultLoggingConventionTests` detected records via `<Clone>$`, which record
  *structs* do not have, so `KeyBinding` was invisible to a scan two documents claimed pinned it.
  Widened and **mutation-checked in both directions**.
- **H-B/H-C** — the same defect class as C1 and H-A, now at the cancellation boundary: an audit that
  could be cancelled out from under an already-committed re-wrap, and a counter that erased a tenant
  it could not vouch for. H-C sits in shared infrastructure Phases 8/11 are told to consume, which
  is why it was not deferred.
- **H-D** — "no elevation" was true of the database and overstated about the application.
  `TenantScopeConventionTests` now fences the seam; Phase 14 supplies real authorization.
- **H-D1/H-D2** — the two stale doc claims, H-D2 being the dangerous one: `phase-2.md` said rotation
  "retires the old version", which the code deliberately does not do and must not.
- **M-6** — assessed and **upheld, not changed**: an adversary who can write `wrapped_dek` writes
  `key_id` in the same statement, so binding over it closes nothing, while the mismatched pair it
  would catch already fails. The real residual is downgrade persistence, whose fix is the retirement
  floor — Phase 15, not an associated-data change.

**Recorded, not fixed (new, found while dispositioning H-D):**
`DataKeyService.GetOrCreateActiveAsync` mints a tenant's root DEK with **no audit row** — `IAuditLog`
is not even injected. → **Phase 13**, with the audit cluster, gated on M4.

**Carry-forward unchanged:** no phase owns the **logging pipeline** (H4/H5) or **deployment
packaging** — H4/H5 stay "Phase 2 hardening" on purpose, because moving logging findings into a
key-custody phase would launder the gap rather than close it · the **alpine→Debian(glibc)** Postgres
revert (ADR 0009) before any perf work or production packaging · **Phases 3 and 5 untouched** since
the fan-out — `phase/3-connector` at `67cc648`, `phase/5-content` at `3a24ccd`.

**Env prereqs unchanged:** SAC off; root stack + lab fleet up; `dotnet` at `C:\Program Files\dotnet`;
apply `db/roles.sql` after `dotnet ef database update`.

### 2026-07-25 — Phase 2 remediated but NOT merge-ready · 8 re-review findings open
Phase 2 vault sits on **`phase/2-vault`, unmerged, 14 commits ahead of `main`** (code pushed to origin
at `4a5c955`; this log entry is the 15th). Seven of those are the **remediation arc**: keystone (`a50d9ec`) → H1 envelope binding
(`ca54bec`) → review record (`d22ce83`) → C1 tenancy scope (`20b721d`) → C2/C3/C4 key custody
(`e47735f`) → H3 + disposition (`8dcf349`, `c557c41`) → CR-1/C-A/H-A (`4a5c955`). The other seven
(`17e40a2`…`305cc81`) are the original module build and the redaction-belt work that preceded the
review. **Vault 54/54, IntegrationTests 36/36, Contracts 19/19.** Host boots, `/health` 200.

**Remediation.** All four original criticals closed, plus H1/H2/H3/H6. A fresh-session re-review of
the remediated code then found **2 new criticals — both author-introduced by the remediation
itself** — and H-A; all three are fixed in `4a5c955`, each proven red-first against the unmodified
code. **C-A is bounded, not eliminated**: the convergence target is authoritative at read time, but a
rotation by another process mid-sweep still leaves this one on a stale target, recoverable by
re-running. Recorded in [ADR 0014](adr/0014-system-tenancy-scope.md), not glossed.

**STILL BLOCKING MERGE — 8 of 11 re-review findings are open and undispositioned.** H-1 (`KekKeyset`
is shallow — `Snapshot()`/`Get()` hand out live KEK arrays while the docs claim a copy) · H-2
(`LoadAsync` taking the lock made the read path require *write* access, breaking a read-only key
mount) · H-3 (a throwing directory fsync on musl reports failure after the rename committed) ·
H-B/H-C (cancellation: audit skipped after a committed re-wrap; a committed tenant reported as not
attempted) · H-D (the "no elevation" claim holds at the database layer, overstated at the application
layer) · **H-D1/H-D2 (the ADR 0012 corrections never propagated to `phase-2.md`/ROADMAP — and H-D2 is
dangerous: `phase-2.md` still says rotation "retires the old version", which the code deliberately
does not do; implementing the doc would delete superseded versions and strand every unconverged
DEK)** · mediums **M-1** (the concurrency test runs its two rotations sequentially, so it would pass
with the lock deleted), **M-2** (nothing tests durability), **M-6** (`key_id` excluded from the DEK
binding permits retired-KEK replay).

**Two owner decisions before merge.** (1) **The fork** — commit to production multi-process rotation
now, or declare the vault correct for single-process and defer multi-process with a named owner.
Several open findings (H-2, H-3, M-1, and C-A's residual window) only matter under the first. (2)
**Whether to get one cold or human review of key custody** before merging: two of the criticals were
introduced by the remediation and found only on re-review, and every review so far has been run by
the same author as the code.

**Carry-forward.** No phase owns the logging pipeline or application deployment (H3/H4/H5 and H7 are
parked as "Phase 2 hardening" only because Phase 2 accepts them; ADR 0009's glibc carry-over has the
same problem) · the alpine→Debian Postgres revert is still required before any perf work or
production packaging · **Phases 3 and 5 remain `in-progress` and were not resumed this session** —
their branches are untouched since the fan-out.

### 2026-07-25 (earlier) — superseded by the two entries above
*Committed directly to `main` as `42529db` while the work continued on the branch, so it was the one
session-log entry the branch never had — and the only conflict in the Phase 2 merge. Kept because a
record should not vanish, but **every number and instruction in it is obsolete**: it describes tip
`7195bee` at Vault 24/24, and the "pending exception-scrub change" it gates on was applied long
before the branch reached its own 2026-07-25 entry.*

**Phase 2 was GREEN on `phase/2-vault`** at tip `7195bee`, Vault 24/24, Contracts 19/19,
Integration 34/34. Branch history to that point: `17e40a2` (WIP dump from the killed fan-out agent) →
`68eb038` (a **test-only** KEK/tenant collision — tenants were `static`, so methods sharing a tenant
on the shared collection-fixture DB read DEKs wrapped under a *different* per-method in-memory KEK
keyset → `KeyNotFoundException`; fixed by making tenant ids instance fields, mirroring production's
one-stable-KEK / many-tenants shape — no crypto change) → `7195bee` (an error-path NeverLog test
that stores a real secret, resolves a non-existent id to drive the not-found branch, and scans both
the captured log body and the thrown exception object in UTF-8/base64/hex/lowercase-hex).

Its pending item — scrubbing the **exception object** in `SecretRedactingLoggerProvider` via a
`RedactedException` wrapper — was applied, and then **substantially revised**: ADR 0012 decision E
now gates the replacement on the belt being armed, because unconditionally dropping
`InnerException`/`Data` was net-negative while nothing registers a sentinel.

Its "resume order" is done: the change landed, and the merge and full-suite re-run it asked for are
what this merge commit performs.

### 2026-07-24 — Merged to main · H1 placed · 2/3/5 fan-out launched
The C1 slice merged to `main` (`d69f0c3`, `--no-ff`), **53/53 green on main**, pushed
(`9ae5be0..d69f0c3`). **H1 placed** as **Phase 14 — Identity & access** (`da711ce`): parallel,
depends on 1, prerequisite of Phase 12; the number is a label, build-order is the *Depends on*
column.

**First parallel fan-out launched** — Phases **2 (Vault)**, **3 (Connector)**, **5 (Content)** set
to `in-progress` and dispatched as **worktree-isolated background agents** (WORKFLOW.md §2 level-3),
each on its own branch (`phase/2-vault`, `phase/3-connector`, `phase/5-content`), briefed to its
exit criteria + CLAUDE.md constraints, told to run tests and **NOT merge**. Lab fleet is up
(2201–2205) for Phase 3's SSH tests. **Integration is one-at-a-time on `main` per WORKFLOW.md §4**,
with review of each before merge — Phase 2's crypto and credential-safety invariants especially.
Agents were told **not to amend the frozen content vocabulary** (it was swept for exactly this) and
**not to run `ef database update` against the dev DB** (tests use ephemeral DBs, so parallel runs
don't collide).

### 2026-07-24 — C1 CLOSED · Phase 1 complete · 2/3/5 unblocked
Round 3 (`a8aaa0e`) cleared its fresh-session review with **no CRITICAL/HIGH/MEDIUM findings** and
an explicit **YES** on the primary question: the content vocabulary is complete for Phase 5's
day-one needs — every ROADMAP:109 feed and every lab distro has a representable path, all six
artifacts (entity, migration, snapshot, both schemas, `db/schema.sql`) agree, and no prior-round
fix regressed. One LOW: Rocky/Alma-via-RHSA carries a per-rebuild-version precision caveat that is
a **Phase 6 comparator** concern (revisit before assessment ships), not a vocabulary gap.

**Actions taken:** dropped the `complete*` asterisk (Phase 1 → **complete**); marked C1
**resolved**; set Phases 2/3/5 → **ready** and lifted the fan-out block. The C1 slice is three
commits on `phase-1/c1-content-catalogue`: `37502b3` (scope + catalogue) → `953a2a5` (round-2
remediation) → `a8aaa0e` (Debian DSA + sweep). **Not yet merged to `main`, not pushed.**

**Next session:** (1) merge the branch to `main` per WORKFLOW.md §4 and re-run tests on `main`;
(2) decide where **H1 (auth/RBAC)** lands — still on no phase, and Phase 12 needs it; (3) the cheap
**M5/M8/M9** hardening for the 8 pre-existing tables; (4) start the **2/3/5 parallel fan-out**
(level-3 dispatched worktrees, per WORKFLOW.md §2). Env prereqs unchanged (SAC off; `docker compose
up -d`; apply `db/roles.sql` for the `patchmgmt_content` dev password).

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
