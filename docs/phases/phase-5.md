# Phase 5 — Content Ingestion (parallel)

> Ingest authoritative vulnerability and patch content from eight public feeds, normalize it into
> the frozen Phase-1 catalogue, and keep the refresh incremental and idempotent. A fresh session
> can execute this doc standalone.

## Objective

Eight feed connectors — NVD, CISA KEV, EPSS, Ubuntu USN, Debian DSA, RHSA, MSRC and
`wsusscn2.cab` — normalized into `content_sources`, `advisories`, `advisory_affects`, `patches`
and `patch_supersedence`, with **provenance recorded per record** and refresh that is both
**incremental** (cursor-driven) and **idempotent** (upsert on the frozen unique keys).

> **As built (this slice):** the module and all eight connectors exist and compile, the contract
> surface is in place, and the module is **proven reachable in the shipped host**. **No connector
> has been run against its live feed, and no parsing test exists yet.** Every exit criterion below
> is unticked, deliberately. See "Status" at the bottom for what is and is not claimed.

## Why content is global, not tenant-scoped

The five catalogue tables carry **no `tenant_id` and no RLS** ([ADR 0010](../adr/0010-global-content-catalogue.md)) —
the single named exemption to CLAUDE.md §4.1. The content is public vendor data, byte-identical for
every tenant; per-tenant copies would multiply the corpus by tenant count for zero isolation
benefit, and would force this sync into a per-tenant loop it has no tenant context for (review M6).

Isolation is **by role, not by row**:

| Role | Catalogue access |
|------|------------------|
| `patchmgmt_app` (request path) | SELECT on advisories/affects/patches/supersedence. **No access to `content_sources`** — its `cursor`/`last_error` embed internal URLs |
| `patchmgmt_content` (this phase) | SELECT, INSERT, UPDATE — **no DELETE**; content retires via `withdrawn_at`, it never vanishes |
| `patchmgmt` (owner) | DDL only |

**Consequence for wiring:** ingestion opens its own connection as `patchmgmt_content` via
`IContentConnectionFactory` (`ConnectionStrings:Content`), never the request-path `AppDbContext`.
The exemption list is asserted by `RlsConventionTests` — a sixth global table cannot appear
silently, and adding one is a frozen-contract change under NEVER #6.

## The abstraction

```csharp
// src/Shared/Contracts/Content — ADR 0018
public interface IContentConnector
{
    string Kind { get; }                                                    // one of Feeds.*
    Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct);
}
```

A connector is a **pure transform**: feed payload → `NormalizedBatch`. It performs no database
writes — persistence and transaction control are `ContentSyncService`'s job — which is what makes
every connector testable from a recorded payload with no database and no network. Each also
exposes a `public static Parse(...)` so the fetch half can be bypassed entirely.

The interface and the normalized model live in **Contracts**, not in the module
([ADR 0018](../adr/0018-content-contract-surface.md)); the Npgsql-carrying seams (`IContentStore`,
`IContentConnectionFactory`) stay in the module so Contracts takes no database dependency.

## The eight feeds — two roles, and the distinction matters

| Feed | Publishes | Notes |
|------|-----------|-------|
| `nvd` | advisories | CVE severity + CVSS. Emits **no** affects rows: NVD carries CPE version *ranges*, which are blind to backports (HARD-PROBLEMS #2). Ranges are deferred as an additive `advisory_ranges` table |
| `usn` | advisory + patch (deb) | Ubuntu. Exact fixed distro version per release; `backported = true` |
| `dsa` | advisory + patch (deb) | Debian. Required by HARD-PROBLEMS #2/#3, not optional |
| `rhsa` | advisory + patch (rpm) | Red Hat CSAF. **Also serves Rocky/Alma**, which rebuild RHEL. Native RLSA/ALSA is deferred until per-rebuild precision proves necessary |
| `msrc` | advisory + patch | CSAF. The Windows **CVE overlay** — "why it matters", keyed CVE→KB |
| `wsusscn2` | patch + supersedence | The offline scan catalogue. The Windows **applicability engine** — "what is missing on this host" |
| `kev` | **nothing** | CISA KEV is an **overlay**: it sets `kev_*` columns and appends provenance. A row with `source='kev'` is rejected by CHECK, and would let one CVE exist as divergent duplicates |
| `epss` | **nothing** | FIRST EPSS, same overlay shape. Scores are probabilities in **[0,1], not percentages** — the CHECK rejects anything else, so a divide-by-100 slip fails loudly instead of inflating every Phase 7 score |

`msrc` + `wsusscn2` together are [ADR 0008](../adr/0008-windows-content-source.md): neither alone
suffices — the cab knows applicability and supersedence, CSAF knows CVEs and severity.

**An overlay applied to a CVE with no advisory yet enriches zero rows.** That is honest and
self-healing, not a bug: it succeeds again once the publisher's advisory is ingested.

## Non-negotiables

- **Raw as sourced.** `fixed_version` and `platform` are stored exactly as the source states them —
  never parsed, split or canonicalized ([ADR 0011](../adr/0011-fixed-version-raw-as-sourced.md)).
  Interpretation is the Phase 6 comparator's job. Parsing here would bake one distro's semantics
  into data three distros share.
- **Provenance is required and non-empty** (DB CHECK, and `ProvenanceJson` throws on an empty
  list). Every input to a Phase 7 risk score must be traceable to who said it and when — no
  unexplained numbers (CLAUDE.md §4.6).
- **Idempotent and time-bounded** (NEVER #5). Every fetch carries a `CancellationToken` and a
  bounded timeout; every write is an upsert on a frozen unique key, so re-running a sync duplicates
  nothing. `advisory_affects` is keyed `(advisory_id, package_name, ecosystem, platform)` with
  `NULLS NOT DISTINCT` — one USN legitimately fixes the same package at a different version on
  every supported release ([ADR 0011](../adr/0011-fixed-version-raw-as-sourced.md), and
  `ContentCatalogueTests` pins it).
- **A failed sync keeps the old cursor.** It records `failed` + the error and does not advance, so
  a transient outage cannot silently skip a window of content.
- **Supersedence edges form only once both patches exist.** Connectors that carry supersedence
  upsert all patches before any edges (HARD-PROBLEMS #4).

## Owned paths

`src/Modules/Content`, plus `src/Shared/Contracts/Content` ([ADR 0018](../adr/0018-content-contract-surface.md))
and `tests/PatchManagement.Content.Tests`.

## Exit criteria — status

Each criterion names the test that proves it. **Nothing below is ticked yet.**

| # | Criterion | Proven by | Status |
|---|-----------|-----------|--------|
| a | Connectors for all eight feeds, normalizing into the Phase-1 schema | per-feed parse tests over recorded payloads in `Samples/` | ☐ connectors written, **no parsing test exists** |
| b | Refresh is **incremental** — the cursor advances on success and holds on failure | `ContentSyncService` tests over a scripted connector | ☐ |
| c | Refresh is **idempotent** — the same payload twice writes the same rows | store tests against Postgres | ☐ (grain already pinned by `ContentCatalogueTests`) |
| d | **Provenance recorded per record**, non-empty, merged rather than overwritten across feeds | store tests asserting the jsonb merge | ☐ |
| e | Overlays (KEV/EPSS) never insert an advisory and never clobber a publisher's re-sync | store tests | ☐ |
| f | Supersedence chains resolve, including the both-patches-required ordering | store tests | ☐ |
| g | The module is **reachable in the shipped host** | `HostModuleDiscoveryTests.Api_project_ships_the_content_module` + `Real_host_container_resolves_the_content_module` | ☑ **proven red-first**, both failed before the API's `ProjectReference` existed |
| h | The contract surface carries no database dependency | `ContentContractSurfaceTests` | ☑ |
| i | The vocabulary matches the frozen schemas | `ContentVocabularyTests` | ☑ (partial — the `AppDbContext` CHECK copy is still independent; ADR 0018 residual, owner Phase 6) |

## ⚠ Scope: what has NOT been done

- **No connector has ever run against its live feed.** All eight are written from the published
  formats and are unverified against real payloads. A green suite here would be a statement about
  the parser, not about the feed — the same distinction Phase 3 records for WinRM.
- **`wsusscn2.cab` has never been expanded.** `ExpandCabPackageSource` shells out to Windows
  `expand.exe` twice and has never been run against the real ~627 MB cab. It also throws
  `PlatformNotSupportedException` off Windows, so a Linux host that syncs this feed fails at call
  time, not at startup. WiX DTF is the managed alternative if shelling out proves unworkable.
- **Nothing invokes `ContentSyncService`.** There is no Hangfire job, no endpoint and no scheduler,
  so the shipped host can discover the module but cannot start a sync. Same shape as the Phase 2
  rotation trigger, whose owner is **Phase 11** — and this needs the same decision.
- **NVD affected-version ranges** (`advisory_ranges`) and **native Rocky/Alma errata** (RLSA/ALSA)
  are deferred. Both are additive and neither changes the frozen five.
