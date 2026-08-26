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
  on failure; ready-for-assessment on success.

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

**2 of 9 ticked** as of 2026-08-26. Slice 1 (sweep + target policy) landed and criterion (a)
closed against the real fleet the same day; slice 2 (schema) landed the same day too. `main` is
green at **580** across nine projects.

| # | Criterion | Proven by | Status |
|---|-----------|-----------|--------|
| a | Tenant-scoped IP-range/CIDR sweep finds the 5 lab containers on `localhost:2201-2205` and reports open management ports | `LabSweepTests` (5) against the real fleet, plus `NetworkSweeperTests` (11) + `CidrBlockTests` (18) + `TargetPolicyTests` (9) against a fake probe | ☑ — the sweep of `127.0.0.1/32` returns exactly `[2201, 2202, 2203, 2204, 2205]`, compared by **equality** against the ports `lab/docker-compose.yml` publishes, read at test time rather than hardcoded. **Not red-first, and could not be** — see the note below |
| b | OS family classified from banner/probe **before** a connector is chosen | unit tests over captured banners | ☐ |
| c | Candidates persisted to `assets` with `source = 'discovery'`, `managed = false` until inventoried | store integration test against real Postgres | ☐ |
| d | Linux package inventory populated for **all 5 distros** over SSH → `asset_packages` (name, version, epoch, arch, source), plus kernel / OS-release onto `assets` | fleet integration test, per-distro theory | ☐ |
| e | Failure sets the asset state **honestly** — `unreachable` / `auth-failed` / `scan-failed`, never collapsed into compliant (HARD-PROBLEMS #8) | outcome→state mapping tests, including a real wrong-key host | ☐ |
| f | A synthetic "seen but in no inventory" host is flagged unmanaged **with its evidence** (seen at IP X by run Y; absent from AD / DHCP / inventory) | correlation tests — the explainability half is CLAUDE.md §4.6, not decoration | ☐ |
| g | Everything tenant-scoped; RLS holds on every new table; `RlsConventionTests` stays green with **no new exemption** | the existing convention suite, unmodified | ☐ |
| h | Every connector call time-bounded and idempotent (NEVER #5); a re-run writes the **same rows with stable ids**, not merely un-duplicated | idempotency tests, to Phase 5's standard | ☐ |
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
compares it to the checked-in export, which needs a decision about normalisation (a `pg_dump` from a
different client version reorders and rewords enough to make a naive comparison useless — this slice
hit exactly that, twice, on `--no-owner` and `--no-privileges`). That is a piece of test
infrastructure with its own design question, and it belongs to whoever owns the schema-contract
surface rather than to the phase that happened to touch it next.

**It therefore needs a named owner before it can be called a deferral at all**
(`DIFFERENTIATORS.md:88`). Proposed: **Phase 13** (audit, compliance, evidence), which already owns
proving that what is checked in matches what is running. Not assigned here — that is the reader's
call, and until it is assigned this is a flagged gap rather than a deferral.

## Deferrals this phase must itself name

`DIFFERENTIATORS.md:88` — deferring is allowed; deferring **without a named owner** is not.

The lab fleet has **no AD and no DHCP**, so correlation ships as a pluggable evidence-source seam
proven against synthetic / file-backed sources — which is exactly what criterion (f) asks for. Real
LDAP and DHCP-lease ingestion are therefore deferred and need owners assigned before the phase closes.

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
