# Phase 4 — Discovery & Inventory (parallel)

> Find endpoints, capture what's on them, and — critically — surface the machines
> that are on the network but in nobody's inventory. A fresh session can execute
> this doc standalone. Depends on Phase 3 (connector).

## Objective
Network discovery + per-host inventory via the connector, plus **unmanaged-asset
detection** (a designed-in differentiator).

## Discovery
- **Sweep** configured IP ranges/CIDRs (tenant-scoped) for reachable hosts and open
  management ports (22 / 5985 / 5986 / 445).
- Classify OS family from banner/probe before choosing a connector.
- Persist candidates into `assets` with `source = discovery`, `managed = false`
  until inventoried.

## Inventory (per managed host, over the connector)
- **Linux:** enumerate installed packages + versions via the package manager
  (`dpkg-query` / `rpm -qa`), kernel, OS release. Store into `asset_packages`
  (name, version, epoch, arch, source).
- **Windows (later, remote cloud VMs):** installed updates/hotfixes + product
  versions via WMI/PowerShell over WinRM.
- Set the asset **state** honestly: `unreachable` / `auth-failed` / `scan-failed`
  on failure. **On success the state is left alone** — this line used to say
  "ready-for-assessment on success", which names a state the frozen Phase-1 machine does not have.
  Success is `managed = true` plus a fresh package set; the compliance states belong to assessment.

## Unmanaged-asset correlation (differentiator)
- Cross-reference discovered hosts against **AD**, **DHCP leases**, and the managed
  inventory.
- Surface: **present on the network but in no inventory** → flagged unmanaged asset
  with the evidence (seen by sweep at IP X, DHCP lease Y, absent from AD/inventory).
- These are findings the customer's existing tools miss — see `docs/DIFFERENTIATORS.md`.

## Data
Extends Phase 1: `assets` (managed, source), `asset_packages`; a discovery-run record
for provenance; correlation results linking an asset to AD/DHCP evidence.

## Exit criteria — status

Two sources state them. `docs/ROADMAP.md` states them abstractly; the table below is the
**operative** form, because it names observable conditions. A criterion is ticked only when a
named test proves it — never because the code looks right.

**9 of 9 ticked** as of 2026-08-27. `main` is green at **632** across nine projects.

**The exit criteria are met; the PHASE is not closed.** It still owns three inherited deferrals —
**D-301** (host-key store), **D-306** (multi-hop bastion) and **D-310** (per-borrow eviction sweep) —
and `host_keys` still has no writer, so criterion (g) holds for it structurally rather than
behaviourally. Slice 5 is what closes those. `docs/WORKFLOW.md` §5 requires every criterion met AND
tests passing before the status moves; the deferral table requires the owner to discharge or
re-assign what it inherited.

| # | Criterion | Proven by | Status |
|---|-----------|-----------|--------|
| a | Tenant-scoped IP-range/CIDR sweep finds the 5 lab containers on `localhost:2201-2205` and reports open management ports | `LabSweepTests` (5) against the real fleet, plus `NetworkSweeperTests` (11) + `CidrBlockTests` (18) + `TargetPolicyTests` (9) against a fake probe | ☑ — the sweep of `127.0.0.1/32` returns exactly `[2201, 2202, 2203, 2204, 2205]`, compared by **equality** against the ports `lab/docker-compose.yml` publishes, read at test time rather than hardcoded. **Not red-first, and could not be** — see the note below |
| b | OS family classified from banner/probe **before** a connector is chosen | `SshBannerClassifierTests` (17) over **captured** banners (`Samples/PROVENANCE.md`) | ☑ **for what a banner can establish, which is less than expected.** Protocol is settled for all five distros, so the connector choice is always determined. **Family is determined for Debian/Ubuntu only** — Rocky and Alma emit byte-identical `SSH-2.0-OpenSSH_9.9` naming no distro, so they classify `unknown` rather than being guessed as `rhel`. See the note below |
| c | Candidates persisted to `assets` with `source = 'discovery'`, `managed = false` until inventoried | `DiscoveryStoreTests` (11) against real Postgres, as the restricted `patchmgmt_app` role | ☑ — one candidate per **open port**, not per address (ADR 0024's over-split; the lab forces it — five containers share `127.0.0.1`). `hostname` records the observed address rather than inventing a name, because a sweep never logs in. State is `scan-failed`: something answered a TCP probe, which is not a successful scan |
| d | Linux package inventory populated for **all 5 distros** over SSH → `asset_packages` (name, version, epoch, arch, source), plus OS-release onto `assets` | `LabInventoryTests` (12) against the real fleet | ☑ — all five distros, >50 packages each, `source` matching the package manager. **Epoch required fixing the collector**: the rpm query asked only for VERSION-RELEASE, so every epoch was being dropped between a host that knows it and a column built to hold it |
| e | Failure sets the asset state **honestly** — `unreachable` / `auth-failed` / `scan-failed`, never collapsed into compliant (HARD-PROBLEMS #8) | `LabInventoryTests` — a **real** rejected key against a live host, and a real closed port | ☑ — proven by what a host actually did, not by a mapping table. A failed inventory also leaves `last_seen` alone and `managed` false |
| f | A synthetic "seen but in no inventory" host is flagged unmanaged **with its evidence** (seen at IP X by run Y; absent from AD / DHCP / inventory) | `CorrelationTests` (6) over file-backed synthetic sources | ☑ — **and the load-bearing test is the negative one**: a host AD knows about is NOT flagged, even though `managed = false`. Absences are written as rows, not computed and discarded, so the flag is auditable later. Real LDAP/DHCP ingestion is **D-401 / D-402** below |
| g | Everything tenant-scoped; RLS holds on every new table; `RlsConventionTests` stays green with **no new exemption** | `RlsConventionTests` (unmodified allowlist) + `DiscoveryStoreTests` two-tenant cases | ☑ **for the tables that now carry rows.** Two tenants sweeping the same address get separate, mutually invisible assets, runs and evidence — asserted through the real `RlsConnectionInterceptor` as `patchmgmt_app`, not as the owner. `host_keys` has RLS and a policy but **no writer yet**, so its isolation is proven structurally (catalog) and not yet behaviourally; that lands with D-301 in slice 5 |
| h | Every connector call time-bounded and idempotent (NEVER #5); a re-run writes the **same rows with stable ids**, not merely un-duplicated | `Re_running_a_sweep_writes_the_same_rows_with_the_same_ids` + `Re_running_advances_last_seen_on_the_same_row` | ☑ **for discovery.** Asserted on **ids**, not counts: a count is satisfied by delete-and-reinsert, by a no-op on conflict, and by a second run that wrote nothing. Findings, packages and evidence all hang off the asset id, so an id that changes silently orphans them. **Not yet closed for inventory** — slice 3 has no writes to be idempotent about |
| i | The Discovery module is **reachable in the shipped host** | `Api_project_ships_the_discovery_module` + `Real_host_container_resolves_the_discovery_module` | ☑ **proven red-first**, both failed before `PatchManagement.Api.csproj` gained its `ProjectReference` — the deps.json guard on the missing entry, the container guard on a null `INetworkSweeper` |

**Why (i) is on the list from day one.** The unreferenced-module defect has now shipped three
times — the Vault at `a50d9ec`, Phase 3's WIP, and Phase 5's foundation slice. Phase 4 adds the
fourth module, so the reachability test is written before the module exists, not after.

## This phase runs on `main`, by explicit decision

**Deviation from WORKFLOW §4, decided 2026-08-26 and recorded here rather than left implicit.**
Phase 4 commits directly to `main`; no `phase/4-discovery` branch is cut.

The branch convention exists to keep `main` green while several phases are in flight and to give the
§4 merge sequence something to merge. Neither applies here: this is a **single-worktree setup with
nothing else in flight**, so a phase branch would be overhead that buys no isolation — the merge
sequence would be a fast-forward of one branch onto a `main` no one else is touching.

What is given up, stated plainly so it is not rediscovered later: **`main` is no longer guaranteed
green between slices.** A slice that lands red leaves `main` red until the next commit, where the
branch convention would have contained it. That is the accepted cost, and it raises the bar on the
red-first discipline rather than lowering it — each slice's green run is what keeps `main` honest,
because nothing else will.

If a second phase starts in parallel, this decision lapses and the branch convention resumes.

## Inherited deferrals — this phase owns three

Each was verified **in code** at `48f3cf1` when the phase opened. None is assumed done.

| ID | Verified state at phase open | What closing it requires |
|----|------------------------------|--------------------------|
| **D-301** — persistent verified-host-key (TOFU) store | **OPEN.** `ConnectorSecurityOptions.cs:26` is a single bool; `SshNetSessionFactory.cs:278-279` sets `e.CanTrust = _security.AllowUnknownHostKeys` — a blanket yes/no. No fingerprint is read, compared or persisted anywhere in `src/` | A `host_keys` store, and a test proving a **changed** fingerprint is refused. Until then the `AllowUnknownHostKeys` gate stands and the connector cannot be pointed at a real fleet |
| **D-306** — multi-hop (>1) bastion chains | **OPEN, and larger than the factory.** `SshNetSessionFactory.cs:184-190` refuses `Hops.Count > 1` by name (`BastionPlanningTests.cs:105-127` proves it), but **that branch is unreachable from the planner**: `EndpointTarget.Bastion` is a single `BastionHop?`, so `ConnectionPlanner.Plan` can only ever emit 0 or 1 hops. The two-hop plan in that test is hand-constructed | A change to the **topology model on the target** — a `Shared/Contracts/Connectors` change under ADR 0017, and therefore a NEVER #6 ask — not merely implementing a loop |
| **D-310** — `AcquireAsync` runs a full eviction sweep per borrow | **OPEN.** `SshConnectionPool.AcquireAsync:80` calls `EvictIdle()` on every borrow; `EvictIdle` takes `lock (_lifetime)` and scans all entries, so acquires serialise on an O(entries) scan | **Measurement, not reasoning.** A sweep is the first thing to borrow hard against many hosts at once. Whether dropping the call changes eviction timing observably is the question to answer with evidence |

**A name collision worth knowing before reading the connector.** `ConnectionKey.HostKeyFor` is a
**governor concurrency key**, not a cryptographic host key. Grepping `HostKey` in `src/` returns it
alongside the D-301 policy line; skimming the results could suggest a key store exists. It does not.

## The sweep is the first feature that can contact an arbitrary IP

`.claude/hooks/lab_only_guard.py` (ADR 0007) inspects **Bash `ssh`/`scp`/`sftp` command strings**. It
structurally cannot see a socket opened by our own C#. Every prior phase reached endpoints only along
paths that hook could observe; a CIDR sweep does not.

So NEVER #4 needs an **in-product** equivalent: a dev-mode target allowlist that refuses to sweep
anything outside loopback, **defaulted closed**, in the same shape as
`ConnectorSecurityOptions.AllowUnknownHostKeys` — configuration, opt-in per environment, and the
gating is the point rather than a side effect. It ships in the sweep slice, not as a later addition.

### Landed 2026-08-26 (slice 1)

`DiscoverySecurityOptions.AllowedTargets` — empty by default, so a deployment that has not declared
its scope sweeps nothing. `DiscoveryTargetPolicy` evaluates every parsed range **before a socket is
opened**, and a request is permitted only when a single allowed block contains it *entirely*;
partial overlap is refused rather than clipped. `appsettings.Development.json` declares
`127.0.0.0/8` and nothing else; the production baseline in `appsettings.json` declares nothing.

Two properties are worth separating, because only one of them is about the sweeper:

- **The policy stops the sweep.** `TargetPolicyTests` asserts on the *probe attempt log*, not on the
  returned host list — "no hosts came back" is also what a fully-executed sweep of an empty subnet
  looks like, so only the absence of attempts distinguishes refusing to look from looking and
  finding nothing.
- **The policy stops the module.** `SocketChokePointTests` pins `src/Modules/Discovery` to exactly
  one file that may open a network connection. Without it, a later slice could reach the network
  down a freshly-written second path and leave every policy test green. Widening its allowlist is
  the place that decision has to be recorded — inventory (slice 3) will need it.

**A name collision the full suite caught, worth recording because the obvious fix was the wrong
one.** `INetworkSweeper`'s method was first written as `SweepAsync`, which turned
`TenantScopeConventionTests` red — that Phase 2 guard fences ADR 0014's cross-tenant seam with a
repo-wide source scan whose vocabulary includes the bare token `SweepAsync`. A network sweep and a
tenant sweep are unrelated, but the scan cannot tell them apart.

The tempting fixes were both wrong. Adding the Discovery files to that guard's allowlist would blind
it to a *genuine* cross-tenant call from this module later — it is an allowlist of files, not of
tokens. Loosening the guard's vocabulary would be Phase 4 weakening a Phase 2 convention to suit
itself. So the newcomer gave way: the method is `ScanAsync`, the nouns stay `Sweep*` because that is
the domain's word, and `INetworkSweeper` carries a comment saying why, so it does not get tidied
back.

Separately, and **for that guard's owner rather than this phase**: matching the bare token
`SweepAsync` anywhere under `src/` will keep producing false positives as the tree grows, and a
convention test that cries wolf is one people learn to silence. Worth tightening to co-occurrence
with `ITenantScopeFactory` — but by Phase 2/15, who own it.

**One residual, named rather than left to be rediscovered.** `NetworkSweeper` creates one task per
address up front and lets `MaxConcurrentProbes` throttle them at a semaphore. Concurrency is
genuinely bounded — that is what the cap is for — but *task creation* is not: a `/16` allocates
65,536 pending waiters before the first probe returns. It is correct and the memory is small, so it
is not worth churning now; it is worth revisiting in slice 3, where address counts stop being
hypothetical, alongside **D-310** (the pool's per-borrow eviction sweep), which this phase already
owns and which is the same question one layer down.

### Criterion (a) closed 2026-08-26 — and it was NOT red-first

Stated plainly because the standing discipline says red-first: **no red run was available for this
test, and pretending otherwise would be the dishonest option.** The sweep was already implemented and
already green — that work was proven red-first in slice 1, where all nine policy and reachability
tests failed before the guard existed. A fleet test written afterwards can only confirm what the
unit suite already established; there was nothing left to implement that it could fail against.

It ran green on its first execution, which was not a foregone conclusion: `TcpPortProbe` is the one
component the unit suite deliberately never exercises — it substitutes a fake probe, because a suite
that reached the network to prove the network guard works would be doing the thing the guard forbids
— so before this suite existed, the only code in the module that opens a socket had never touched a
real TCP stack.

**What replaced the red run: two mutations, because a green test that cannot fail proves nothing.**

- Appending a port nothing publishes turned it red, and the failure printed the fleet as observed:
  `Expected: [···, 2202, 2203, 2204, 2205, 2299]` / `Actual: [···, 2202, 2203, 2204, 2205]`.
- Comparing against an empty list printed the discovered set in full —
  `Actual: [2201, 2202, 2203, 2204, 2205]` — which is exactly what `docker ps` publishes:
  2201 ubuntu2204, 2202 ubuntu2404, 2203 debian12, 2204 rocky9, 2205 alma9.

`A_port_nothing_listens_on_is_reported_closed` is the standing control: a probe that called every
port open would satisfy "all five answered" perfectly, so a port bound and released a moment earlier
must come back closed. And `A_non_lab_range_is_still_refused_with_the_real_probe` re-proves NEVER #4
with the real probe wired in, since every other policy proof substitutes it.

**One thing this suite does not claim.** The lab publishes all five distros on `127.0.0.1` at
different ports, so five containers are observed as one host with five open ports, not as five
hosts. Establishing that those endpoints are five distinct machines requires a login, which is
slice 3's job.

### Landed 2026-08-26 (slice 2, second half) — the store and upsert

`IDiscoveryService` sweeps, then persists: a `discovery_runs` row opened **before** probing and
closed after, one `assets` candidate per open port, and an `asset_evidence` row per candidate.

**Red-first, and the red is the interesting part.** The naive implementation — insert a candidate
per sighting — was written first and run against real Postgres. Five tests failed with:

```
Npgsql.PostgresException : 23505: duplicate key value violates unique constraint
"ux_assets_discovery_candidate"
```

That single line is worth more than the green run: it proves the slice-2 natural key is real and
biting, that the partial index actually covers the coordinates the store writes, and that a
re-sweep genuinely collides rather than quietly duplicating.

**A second red followed the fix**, and is recorded because the next person will hit it too. The
first `ON CONFLICT` named only `WHERE source = 'discovery'` and every test failed with
`42P10: there is no unique or exclusion constraint matching the ON CONFLICT specification`.
Postgres infers a partial index only when the conflict predicate implies the index's, and its prover
does not accept a prefix — the predicate must be repeated in **full**, NULL clauses included.

**`DO UPDATE`, not `DO NOTHING`.** The latter returns no row, so the caller learns no id and must
re-SELECT — and `last_seen` would never advance, making every live host read as abandoned
(HARD-PROBLEMS #10). `Re_running_advances_last_seen_on_the_same_row` pins that.

**The store is scoped, the sweep stays singleton.** The store consumes `AppDbContext`, which is
scoped and carries the tenant through `RlsConnectionInterceptor`. Registering the service as a
singleton would capture it — the captive dependency that stopped the Connectors module resolving at
all. Raw SQL is issued on a connection opened *through EF* so the interceptor fires and sets
`app.tenant_id`; opened any other way the policy denies all and the insert fails closed.

**A fourth Postgres fixture.** `PatchManagement.IntegrationTests` cannot host these tests: it
deliberately references no module, and referencing Discovery would copy the DLL into its output and
make `Real_host_container_resolves_the_discovery_module` pass on that copy while the shipped API
lacked the module. Collapsing the four fixtures onto `TestSupport` is the right fix and is adjacent
to **D-308** — flagged, not done here.

**Nothing invokes `IDiscoveryService`** — no job, no endpoint. Same shape as `ContentSyncService`,
and it needs the same decision (owner: Phase 11).

### Landed 2026-08-26 (slice 3) — classification, inventory, honest failure states

**Criterion (b) closes for less than the wording implies, and the captures are why.** All five lab
banners were captured to `tests/PatchManagement.Discovery.Tests/Samples/` under the Phase 5
PROVENANCE rule (real payloads only; a fixture written to the parser proves nothing). What they show:

| Distro | Banner |
|---|---|
| Ubuntu 22.04 / 24.04 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.16` / `…9.6p1 Ubuntu-3ubuntu13.18` |
| Debian 12 | `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10` |
| Rocky 9 | `SSH-2.0-OpenSSH_9.9` |
| Alma 9 | `SSH-2.0-OpenSSH_9.9` |

**Rocky and Alma are byte-identical and name nothing.** The tempting rule — "no vendor suffix ⇒ Red
Hat family" — is true on this fleet and false everywhere else (upstream OpenSSH, Alpine, anything
that ships the version string unpatched), so it would be right for the lab and wrong in the field
with a green suite either way. The classifier reports `unknown`. Both identical captures are kept
deliberately: one alone would read as a single unrecognised value rather than as proof the banner
carries no distro information.

So **protocol** is always determined — which is what actually selects a connector — and **family**
is determined only for the Debian side. Establishing that a bare banner is Rocky rather than Alma
needs `/etc/os-release`, which needs a login, which is inventory.

**Criterion (e) is proven by a host, not by a table.** The connector already mapped `AuthFailed` to
`auth-failed` in C#; a unit test asserting that maps a constant to a constant. What was unproven is
that a host which *actually rejects a credential* is classified as a rejection rather than a
timeout — the exact confusion HARD-PROBLEMS #12 records happening once already. `InventoryService`
therefore probes `TestConnectivityAsync` **first**: `EndpointFactsCollector` reports every failure as
one exception type, so a plain try/catch would record `scan-failed` for a rejected credential, an
unreachable host and a broken command alike.

**A successful inventory sets no state, and that is deliberate.** The frozen Phase-1 machine has no
"inventoried" state; success is recorded as `managed = true` with a fresh package set. **The phase
doc's own wording — "ready-for-assessment on success" — names a state that does not exist**, and is
corrected below rather than implemented.

## Test-fidelity gap: hand-built objects are not the shipped composition — owner TBD

**Found 2026-08-26 while fixing `EndpointFactsCollector`'s DI resolution, and recorded rather than
fixed. It is not Phase 4's to close.**

That collector took a single `IEndpointConnector` while the module registers two, so DI handed every
container-resolved instance the **last** registration — `WinRmConnector` — whatever protocol the
target named. It is fixed now (it takes `IEndpointConnectorRegistry`), and
`FactsCollectorResolutionTests` pins the dispatch **through the real `AddConnectorsModule`
container**.

**The reason it survived is worth stating precisely, because a first reading gets it wrong.** It was
not that a test built the collector by hand and so missed the wiring — **nothing built it at all.**
A repo-wide search found no test that constructed or exercised `EndpointFactsCollector` or
`LinuxFactsParser` in any suite; the only references were source-scanning convention tests. It
shipped in Phase 3 with **no behavioural coverage of any kind**, and Phase 4's inventory slice was
the first code anywhere to resolve it.

**The general gap.** `Connectors.IntegrationTests` proves the connector works against the real
fleet by composing it **by hand** — `new SshConnector(...)` with explicit collaborators. That is
the right way to test the connector's behaviour, and it is why the fleet suite is trustworthy. But
it means **no test in that suite exercises the container the host actually builds**, so any defect
that lives purely in `AddConnectorsModule` — a wrong lifetime, a captive dependency, a
single-service resolution with two registrations — is invisible to it. Two of those three have now
bitten this repo.

`HostModuleDiscoveryTests` covers the adjacent question (is the module *reachable*), not this one
(does the module resolve the *right* collaborators).

**Not fixed here**, and it needs an owner before it is a deferral at all
(`DIFFERENTIATORS.md:88`). The fix is a small container-fidelity suite per module — resolve each
public service from a real composition and assert its collaborators — which is test infrastructure
with its own shape, belonging to whoever owns the connector surface rather than to the phase that
tripped over it. **Proposed: Phase 8**, which inherits the connector (D-302, D-303, D-304, D-309)
and is where an unexercised WinRM path first becomes load-bearing.

## `db/schema.sql` has no drift test — candidate deferral, needs an owner

**Flagged, deliberately NOT fixed here.** `db/schema.sql` is a `pg_dump --schema-only --no-owner`
export. It was regenerated after the slice-2 migration and the diff was verified purely additive —
only the new objects, no incidental drift from a different dump invocation.

**Nothing enforces that it stays current.** Review **L4** named this in Phase 1 and it is still open:
of the five frozen contract artifacts, this is the one with an authoritative source (the migrations)
and no test that fails when the export falls behind it. [ADR 0021](../adr/0021-openapi-design-first.md)
states the invariant this violates — *every frozen contract has exactly one authoritative artifact,
and a test that fails when anything drifts from it* — and records that OpenAPI was the only contract
missing both halves. `db/schema.sql` is missing the second half.

**Why Phase 4 is not the phase to close it.** The fix is a test that dumps the live schema and
compares it to the checked-in export, and that needs a normalisation decision this slice kept
running into:

- Flag choice changes the output wholesale. `--no-privileges` and `--no-owner` each produced an
  export differing from the checked-in one for reasons unrelated to the schema.
- **`pg_dump` emits a fresh random nonce on every run.** Each export opens with
  `\restrict <20-odd random characters>` and closes with the matching `\unrestrict`. Two dumps of a
  byte-identical database therefore differ, always. A naive text comparison would fail on **every**
  run, and the obvious fix — strip those two lines — is the first clause of a normalisation policy
  that should be decided deliberately rather than accreted one surprise at a time.

That is test infrastructure with its own design question, and it belongs to whoever owns the
schema-contract surface rather than to the phase that happened to touch it next.

**It therefore needs a named owner before it can be called a deferral at all**
(`DIFFERENTIATORS.md:88`). Proposed: **Phase 13** (audit, compliance, evidence), which already owns
proving that what is checked in matches what is running. Not assigned here — that is the reader's
call, and until it is assigned this is a flagged gap rather than a deferral.

## Deferrals this phase names — D-401 and D-402

`DIFFERENTIATORS.md:88` — deferring is allowed; deferring **without a named owner** is not. Both
owners below are **proposals awaiting ratification**, not decisions this phase made alone.

The lab has no Active Directory and no DHCP server, so correlation ships as a pluggable
`IAssetEvidenceSource` seam proven against file-backed synthetic sources — which is exactly what
criterion (f) asks for, and what makes "absent from AD" assertable at all. What is deferred is the
*real* ingestion behind that seam.

| ID | Deferred | Proposed owner | Gate — what cannot be claimed until it lands |
|----|----------|----------------|----------------------------------------------|
| **D-401** | Real **Active Directory / LDAP** evidence source | **Phase 14** (identity & access) | The unmanaged finding is only as good as the sources consulted. Until AD is real, "absent from AD" means "absent from a file someone maintained", and the differentiator cannot be demonstrated to a customer against their own estate. Phase 14 is proposed because it is where directory integration already lands — `operators.external_auth_ref` and federated login need an LDAP client, and two LDAP clients in one product is one too many |
| **D-402** | Real **DHCP lease** ingestion | **Phase 11** (scheduling & reporting) | Same gate. A lease file is a point-in-time export; real ingestion is a *scheduled import* with its own freshness question — a stale lease table makes a live host look absent, which manufactures the exact false positive this feature exists to avoid. Phase 11 is proposed because it owns schedules; the freshness rule belongs with whatever runs the import |

**Both share one hazard worth stating once.** `IAssetEvidenceSource` requires a source that cannot be
consulted to **throw**, never to report absence — an unreachable domain controller would otherwise
flag an entire estate as unmanaged, an outage rendered as a finding. That rule is enforced today
(`An_unreadable_source_fails_rather_than_reporting_every_host_absent`) and whoever implements D-401
or D-402 inherits it; a real network client has far more ways to be unavailable than a missing file
does.

**Also not registered by default:** the module registers no `IAssetEvidenceSource`. A deployment
declares its own. Registering a synthetic one by default would let an estate correlate against
nothing while appearing to correlate — and with no sources, every discovered host is reported
unmanaged, which is the honest answer when nothing has been asked.

### Landed 2026-08-26 (slice 2) — schema

`discovery_runs`, `asset_evidence`, `host_keys`, all tenant-scoped with FORCE RLS and exactly one
`tenant_isolation` policy each, verified in the live catalog. No RLS exemption sought: CLAUDE.md
§4.1's single named exemption stays at five global content tables and `RlsConventionTests`'
allowlist is untouched.

The `assets` edit — `endpoint_port` plus `ux_assets_discovery_candidate` — is
[ADR 0024](../adr/0024-asset-discovery-natural-key.md), written **before** the migration because it
changes a frozen contract.

**Two departures from house convention, both deliberate and both now asserted rather than assumed:**

- **The grants are not full CRUD.** `discovery_runs` and `host_keys` have no DELETE; `asset_evidence`
  is append-only like `audit_log`. Every other tenant table is full CRUD, so a migration granting
  these three the same way would look entirely normal in review and silently remove three
  guarantees. `Phase4_tables_carry_their_declared_grant_posture_including_what_is_withheld` asserts
  the **absence** of each withheld privilege, which is the load-bearing half.
- **`asset_evidence` is RESTRICT, not CASCADE**, unlike `asset_packages`. The row is *why* an asset
  is flagged what it is flagged (§4.6); letting a delete erase it would make the flag retroactively
  unexplainable.

## Open asks (NEVER #6) — required before the slices that need them

1. ~~**Schema.**~~ **CLOSED 2026-08-26** — approved and migrated as
   `20260826140155_DiscoveryAssetProvenanceAndHostKeys`. The `assets` natural key it turned on is
   [ADR 0024](../adr/0024-asset-discovery-natural-key.md).
2. **Connector contract, for D-306.** Either widen `EndpointTarget.Bastion` to a list (breaking) or
   add a `BastionChain` alongside it, keeping `Bastion` as the one-hop shorthand (additive).
   **Additive is recommended** — no existing caller changes.

## Slice plan — red-first

| # | Slice | Gated on |
|---|-------|----------|
| 0 | Docs: status → in-progress, this criteria table | — |
| 1 | Sweep + in-product lab-only guard | Docker (lab fleet) |
| 2 | Persistence + RLS | ask 1 · Docker (Postgres) |
| 3 | Inventory over the 5-distro fleet | Docker (lab fleet) |
| 4 | Correlation + evidence | slice 2 |
| 5 | Deferrals: D-301 store, D-306 chain, D-310 measurement | ask 2 |
