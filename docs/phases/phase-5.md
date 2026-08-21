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
| `dsa` | advisory + patch (deb) | Debian. Required by HARD-PROBLEMS #2/#3, not optional. Source is salsa's raw **plain-text** `data/DSA/list` (ADR 0022) — not JSON, and the only form carrying both DSA ids and per-suite fixed versions |
| `rhsa` | advisory + patch (rpm) | Red Hat securitydata. The endpoint returns a **JSON array of summaries** carrying NEVRA strings — not the per-advisory CSAF document. **Also serves Rocky/Alma**, which rebuild RHEL. Native RLSA/ALSA is deferred until per-rebuild precision proves necessary |
| `msrc` | advisory + patch | **CVRF, two calls**: a monthly index then one document per month. The Windows **CVE overlay** — "why it matters", keyed CVE→KB |
| `wsusscn2` | patch + supersedence | The offline scan catalogue. The Windows **applicability engine** — "what is missing on this host". A 658 MB multi-file cab: `index.xml` + a graph cab + **74 detail shards** keyed by `RevisionId` (ADR 0020's vendored WiX DTF reads it) |
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

`src/Modules/Content`, plus `src/Shared/Contracts/Content` ([ADR 0018](../adr/0018-content-contract-surface.md)),
`tests/PatchManagement.Content.Tests` and `tests/PatchManagement.Content.IntegrationTests`.

> **Why there are two test projects.** `Content.Tests` is deliberately infrastructure-free — no
> Postgres, no fleet, no network — and runs 148 tests in under a second. The store criteria (c)–(f)
> need Postgres *and* `ContentStore`, and neither existing project can host that:
> `PatchManagement.IntegrationTests` has `PostgresFixture` but **must never reference the Content
> module**, because `HostModuleDiscoveryTests` only works while the module's sole path into that
> project's output is the API's own `ProjectReference` (ADR 0018). So the store suite gets its own
> project, exactly as Phase 3 split `Connectors.Tests` from `Connectors.IntegrationTests`.

## Exit criteria — status

Each criterion names the test that proves it. **8 of 9 ticked** as of 2026-08-21 — criterion (a) completed with the wsusscn2 rewrite.
**(a) is complete as of 2026-08-21 — 8 of 8 feeds.** The one criterion still open is **(b)**, which
is half-built rather than half-tested.
A criterion is ticked only when a named test proves it — never because the code looks right.

| # | Criterion | Proven by | Status |
|---|-----------|-----------|--------|
| a | Connectors for all eight feeds, normalizing into the Phase-1 schema | per-feed parse tests over **captured** payloads in `Samples/` | ☑ **8 of 8** — every feed covered by its `*ParseTests` against real captures. `rhsa`, `msrc`, `dsa` and **`wsusscn2`** were all rewritten 2026-08-21 against captured payloads, and each **fails loudly** on an unexpected shape. `wsusscn2` additionally has `Wsusscn2CatalogTests` against the real 658 MB cab — the extractor's first successful run (D-504 closed) |
| b | Refresh is **incremental** — the cursor advances on success and holds on failure | `ContentSyncServiceTests` over a scripted connector | ◐ — the **advance-or-hold half is proven** (`A_failed_sync_holds_the_cursor_and_records_the_failure_on_the_feed_row`, `A_successful_sync_advances_the_cursor_and_hands_it_to_the_next_run`). Stays unticked because **incrementality is unimplemented**, not untested: cursors are emitted, persisted and handed back, but no connector ever sends one to a feed |
| c | Refresh is **idempotent** — the same payload twice writes the same rows | `ContentIdempotencyTests` (7) + `ContentSyncServiceTests` atomicity | ☑ — advisories, affects, patches, feed rows and supersedence edges each re-ingested; ids proven **stable**, not merely unduplicated. Includes the NULL-platform case, which is the only proof the store's arbiter resolves to the `NULLS NOT DISTINCT` index rather than silently inserting a duplicate per refresh |
| d | **Provenance recorded per record**, non-empty, merged rather than overwritten across feeds | `ContentProvenanceTests` (5) | ☑ — an advisory touched by nvd+kev+epss keeps all three; a publisher re-sync replaces **only its own** entry and neither drops the others nor appends a second of its own |
| e | Overlays (KEV/EPSS) never insert an advisory and never clobber a publisher's re-sync | `ContentOverlayTests` (6) | ☑ — an overlay for an unpublished CVE writes nothing and self-heals; a publisher re-sync leaves `kev_*`/`epss_*` intact. **See D-502**: a related gap this criterion does not cover |
| f | Supersedence chains resolve, including the both-patches-required ordering | `ContentSupersedenceTests` (6) | ☑ — the ordering case is asserted through `ContentSyncService` with the superseding patch **first** in the batch, so a one-pass implementation fails it; a three-patch chain walks to a single head. **See D-503**: cycles |
| g | The module is **reachable in the shipped host** | `HostModuleDiscoveryTests.Api_project_ships_the_content_module` + `Real_host_container_resolves_the_content_module` | ☑ **proven red-first**, both failed before the API's `ProjectReference` existed |
| h | The contract surface carries no database dependency | `ContentContractSurfaceTests` | ☑ |
| i | The vocabulary matches the frozen schemas | `ContentVocabularyTests` | ☑ (partial — the `AppDbContext` CHECK copy is still independent; ADR 0018 residual, owner Phase 6) |

## ⚠ Three connectors could not work against their real feeds — found 2026-07-28, ALL THREE FIXED 2026-08-21

> **Status.** All three were rewritten against real captured payloads on 2026-08-21 and now work;
> each **fails loudly** on an unexpected shape rather than returning an empty batch. The findings
> below are kept as the record of what was wrong, because the rewrites' shape checks exist to stop
> exactly this recurring.
>
> **What the real formats turned out to be**, neither matching the guess recorded further down:
>
> - **`rhsa`** — the endpoint returns a **JSON array of summary objects** (`RHSA`, `severity`,
>   `released_on`, `CVEs[]`, `released_packages[]` as NEVRA, `resource_url`). Not the per-advisory
>   CSAF document. `released_packages` is not uniformly NEVRA either: some advisories list module
>   streams (`java-21-openjdk-portable-main@aarch64`) with no version at all.
> - **`msrc`** — **two calls**: `cvrf/v3.0/updates` (a 191-entry monthly index) then the month's
>   CVRF document. And **the remediation types are not what the CVRF spec implies** — **Type 2** is
>   the vendor fix carrying the KB, `FixedBuild`, `RestartRequired` and `Supercedence`; **Type 3**
>   has no `Description` at all; **Type 6** repeats a KB. A parser written from the spec reads Type 3
>   as "Vendor Fix", finds nothing, and returns an empty batch reported as `ok`.
> - Two further traps, both now pinned by test: MSRC's `ReleaseDate` is `0001-01-01T00:00:00` with
>   `ReleaseDateSpecified: false` (a sentinel that must not become a date), and Type 2's
>   `Description` is only *sometimes* a KB — for non-Windows products it is a label such as
>   `"Release Notes"`.
> - **`dsa`** — the endpoint 404s; the source is salsa's raw **plain-text** `data/DSA/list`
>   (**ADR 0022**, which lives on `main`; this branch predates the file). Grammar measured across the
>   whole 1.1 MB capture: **indentation is mixed** (525 space-indented lines among 14,846 tabbed),
>   the file is **date-ordered so revisions are prepended** (181 id-order inversions), 217 headers are
>   announcements with no package, 450 ids carry no revision suffix, and 62 suite lines hold an
>   annotation where a version belongs.

## The original finding (2026-07-28), kept as the record

Each connector's own `DefaultEndpoint` was requested during parse-slice-1 planning. **Three of the
seven HTTP connectors do not match reality**, and the failure is not symmetric — one of them
*reports success*.

| Connector | Its `DefaultEndpoint` | Observed | Consequence |
|---|---|---|---|
| `nvd` · `kev` · `epss` | — | **200, shape matches** | tested in slice 1 |
| `usn` | `usn.ubuntu.com/usn-db/database.json` | **200**, root is the expected map, **260 MB** | usable; slice 2 needs a subsetting decision |
| **`dsa`** | `security-tracker.debian.org/tracker/data/dsa.json` | **404** | fetch fails loudly. **Debian publishes no JSON advisory feed at any URL** — see the exhaustive probe below |
| **`rhsa`** | `access.redhat.com/hydra/rest/securitydata/csaf.json` | **200**, but the body is a **JSON array** | `Parse` reads `root.Array("advisories")`; `JsonHelpers.Array` returns `[]` for a non-object receiver, so this yields an **empty batch and a status of `ok`** |
| **`msrc`** | `api.msrc.microsoft.com/cvrf/v3.0/csaf` | **400 Invalid ID** | fetch fails loudly |

**`rhsa` is the dangerous one and belongs in this project's recurring-hazard list.** It does not
throw, does not warn, and `ContentSyncService` records `status = 'ok'` with zero rows written and the
cursor advanced. An operator sees a green sync and an empty catalogue — *reports success while
untrue*, the same class as Phase 2's `Complete` and Phase 3's checks that could not fire.

**`rhsa` and `msrc` also parse invented envelopes.** `RhsaConnector` expects
`root.advisories[]` with `.cvss3`/`.affected[]`; real Red Hat CSAF is
`document.tracking.id` + `vulnerabilities[].product_status.fixed[]` (NEVR strings like
`8Base-Fast-Datapath:network-scripts-openvswitch2.17-0:2.17.0-148.el8fdp.aarch64`). `MsrcConnector`
expects `root.vulnerabilities[].remediations[]`; real MSRC serves CVRF/CSAF documents per month.
Neither resembles the format it claims to consume, so **their `Parse` logic is not merely untested —
it is written against a format no server produces.** Rewriting each against a real captured payload
is the entry condition for its slice.

### DSA — every candidate source probed, 2026-07-29

`dsa`'s endpoint is not a typo to correct. Every plausible Debian source was requested:

| Source | Result | DSA ids? | Per-suite fixed versions? |
|---|---|---|---|
| `tracker/data/dsa.json` *(the connector's endpoint)* | **404** | — | — |
| `tracker/data/DSA/list` | **404** | — | — |
| `tracker/data/json` | 200, **80 MB**, package→CVE→releases | **none — the string `DSA-` does not appear** | per-CVE only |
| `salsa…/security-tracker/raw/master/data/DSA/list` | 200, 1.1 MB, **plain text** | ✅ 6,466 | ✅ |
| `www.debian.org/security/dsa-long.rdf` | 200, 28 KB | ✅ but only **31** items | ❌ |
| `www.debian.org/security/oval/oval-definitions-*.xml` | **403** | — | — |

**Debian publishes no JSON advisory feed.** `DebianDsaConnector` expects a JSON root map of
`DSA-id → {releases: {suite: {packages: {pkg: {version}}}}}`, which matches nothing Debian serves —
the same invented-envelope defect already recorded for `rhsa` and `msrc`. The only canonical source
is line-oriented text:

```
[28 Jul 2026] DSA-6402-1 hplip - security update
	{CVE-2026-8631 CVE-2026-8632}
	[trixie] - hplip 3.22.10+dfsg0-8.1+deb13u1
```

**BUILT 2026-08-21.** The data-source question — whether a `salsa.debian.org` raw-git URL is an
acceptable production dependency — was answered by **ADR 0022** (on `main`; this branch predates the
file): accepted, with the stability risk named and a fail-loud parser as the binding mitigation. The
connector is a line parser over the whole list, covered by `DsaParseTests` against the real capture.

**The edge-case figures quoted here in July were counted from a partial read and are wrong.**
Measured across the whole 1,135,558-byte capture: **6,519** advisories (not 6,466), `<not-affected>`
**×55** (not 52), `<end-of-life>` ×4, `<unfixed>` **×3** (not 2), and 12 suites back to `woody` —
which is right. Three further properties were not noticed at all in July and each would have broken
a parser: **indentation is mixed** (525 space-indented lines among 14,846 tabbed, across 260
advisories), the file is **ordered by date rather than id** so revisions are prepended (179 numbers
with several revisions, 181 inversions), and **450 pre-2007 ids carry no revision suffix**.

**Rejected: sourcing Debian from the CVE-keyed JSON.** It carries no DSA identifiers, so advisories
would have no `external_id` — breaking the frozen `advisories(source, external_id)` uniqueness — and
it drops the advisory-level fixed version HARD-PROBLEMS #2 needs for backport detection.

**Debian's codename map was extended by the DSA slice (2026-08-21), from 5 entries to 13.** It
covered `stretch`…`trixie` only, so the seven older suites the list still carries (`woody`, `sarge`,
`etch`, `lenny`, `squeeze`, `wheezy`, `jessie`) fell through to `debian:<codename>` — **5,240 of the
8,560 suite lines, 61%**. All twelve suites in the capture now map, plus the announced `forky` (14),
added ahead of its first advisory because the platform label is part of row identity and correcting
it after an ingest inserts duplicates rather than updating. `DsaParseTests` asserts that **no** fix
statement in the whole file reaches the raw-codename fallback.

### wsusscn2 — BUILT 2026-08-21 (D-504 closed). The four defects below are the record of what was wrong

> **Status.** The rewrite landed on 2026-08-21 and the extractor ran successfully against the real
> 658 MB cab for the first time. `DtfWsusCatalogSource` reads `index.xml`, resolves a revision to its
> shard by `RANGESTART`, and extracts through the vendored WiX DTF reader (**ADR 0020**, its first
> consumer). `Wsusscn2Connector` joins the graph to the shard blobs and emits patches plus
> supersedence. Covered by `Wsusscn2ParseTests` (captured slice) **and** `Wsusscn2CatalogTests`
> (the real cab, failing rather than skipping if it is absent).
>
> **What the investigation added to the four defects below:**
>
> - **The join key is `RevisionId`** — the blob file name IS the revision id, and `RANGESTART`
>   partitions that space: shard 2 covers 1–626, shard 3 starts at 627, up to 45,415,921.
> - **`RebootBehavior` was located** — it is in `x/<n>`'s `<InstallationBehavior>`, so
>   `requires_reboot` now comes from vendor data. **`Uninstallable` does not exist anywhere** in the
>   `c/` or `x/` blobs, so `reversible` stays false as a stated limit, gating rollback off.
> - **The blobs are XML FRAGMENTS** — several sibling top-level elements, no single root, which
>   `XElement.Parse` rejects outright until wrapped.
> - **One KB can be several updates.** KB5101650 appears as two revisions with different `UpdateId`s;
>   `patches` is unique on `(source, vendor_id)`, so they collapse to one patch with merged edges.
> - **DTF does not make this cross-platform**, contrary to what the note below and
>   `ExpandCabPackageSource` both predicted: it contains no decompressor and P/Invokes
>   `cabinet.dll`, so LZX works because *Windows* decodes it. The explicit platform guard is kept —
>   off Windows a `DllNotFoundException` from inside a P/Invoke is strictly worse.

### The original finding (2026-08-16), kept as the record

The real `lab/content/wsusscn2.cab` (658 MB, fetched Phase 0) had **never been opened**. It was
opened on this Windows box using `C:\Windows\System32\expand.exe`. **No Windows target, VM or WinRM
is needed** — this is a local file, not an endpoint operation, which is why it was reachable now
rather than at Phase 8. Four defects, each confirmed against the real cab.

**1 — `ExpandCabPackageSource` cannot run at all.** `expand.exe` refuses the exact invocation the
code issues:

```
lab/content/wsusscn2.cab: Destination directory required for a multi-file CAB.   (exit 2)
```

`RunExpandAsync` passes a **file** path as the destination. `wsusscn2.cab` is a multi-file cab, so
the **first** call fails, every time, and the code throws `expand.exe failed extracting
'package.cab' (exit 2)`. A directory destination works. The inner `package.cab` is single-file, so
the second call's file destination is fine — the bug is specific to the outer cab.

**2 — the catalogue is sharded; only 1 of 75 cabs is read.** `index.xml` is Microsoft's own manifest:

```xml
<INDEX VERSION="1"><CABLIST XOR="0">
  <CAB NAME="package.cab" />
  <CAB NAME="package2.cab" RANGESTART="0" FILESDIR="1" />
  <CAB NAME="package3.cab" RANGESTART="627" />
  …  <CAB NAME="package75.cab" … />
```

`ExpandCabPackageSource` extracts `package.cab` only and never reads `index.xml`.

**3 — the parse envelope is invented. This is the fourth feed with that defect.** `package.xml`
(114.7 MB, **136,965** `<Update>` elements) carries the update **graph** and nothing else. The
complete set of `<Update>` attributes is `CreationDate, DefaultLanguage, DeploymentAction, IsBundle,
IsLeaf, IsSoftware, RevisionId, RevisionNumber, UpdateId`. Measured occurrences across the whole file:

| Field `Wsusscn2Connector.Parse` reads | Occurrences |
|---|---|
| `KBArticleID` | **0** |
| `Title` | **0** |
| `RebootBehavior` | **0** |
| `Uninstallable` | **0** |
| `IsSoftware="true"` | **0** (all 4,206 are `"false"`) |

**4 — therefore it yields an empty batch and reports `ok`.** The first filter is
`if (kb is empty && isSoftware != "true") continue;`. `KBArticleID` never exists and `IsSoftware` is
never `"true"`, so **all 136,965 updates are skipped**. `ContentSyncService` then records
`status = 'ok'`, 0 patches, and advances the cursor to `PackageId`. Identical in shape to the `rhsa`
defect above, on the feed ADR 0008 designates as the Windows **applicability engine** — and it would
also discard the 14,242 `SupersededBy` blocks / 293,457 `Revision` references that are the entire
Windows half of the HARD-PROBLEMS #4 supersedence DAG.

**What is actually correct** and should be kept: the `SupersededBy → Revision/@Id` inversion matches
the real shape exactly; `UpdateId`/`RevisionId` are real attributes; `PackageId` is a real root
attribute and a sound cursor.

**The real format, mapped** — so the rewrite starts from fact:

```
wsusscn2.cab                     multi-file cab → destination MUST be a directory
├── index.xml                    CABLIST: package.cab + package2..75.cab with RANGESTART offsets
├── package.cab  →  package.xml  the update GRAPH: UpdateId, RevisionId, IsLeaf/IsBundle,
│                                Prerequisites, SupersededBy/Revision/@Id, Categories
└── package2..75.cab             per-update detail, sharded by RANGESTART:
      c/<n>                      <Properties UpdateType="Software|Category">,
                                 <Relationships><SupersededUpdates><UpdateIdentity UpdateID=…>
      l/<lang>/<n>               <LocalizedProperties><Title>… (KB5087058)</Title><Description>
      x/<n>                      <ExtendedProperties MsrcSeverity="Critical">
                                   <KBArticleID>5087058</KBArticleID>
```

So the three fields the parser wanted **do exist — in the shards, not in `package.xml`**:
`KBArticleID` → `x/<n>`; `Title` → `l/<lang>/<n>`; and the software-vs-category discriminator is
`c/<n>`'s `Properties/@UpdateType`, **not** `package.xml`'s `IsSoftware` (which is `"false"`
throughout). `MsrcSeverity` in `x/<n>` is a bonus the current design does not use.

**Not found in the sampled blobs:** `RebootBehavior` and `Uninstallable`. Sample was small — `c/1`,
`c/7`, `x/1`, `l/en/1` — so this is "must be located", not "does not exist".

> **RESOLVED 2026-08-21.** `RebootBehavior` **was located**, in `x/<n>`'s `<InstallationBehavior>`;
> `requires_reboot` now comes from it. `Uninstallable` **does not exist** — zero occurrences across
> all 626 `c/` and `x/` blobs in the shard measured — so `reversible` stays `false` as a stated
> limit, which gates rollback off (DIFFERENTIATORS #1), the safe direction.

**Deferred to its own slice, deliberately — this is a data-source decision, not a parse fix**, the
same call made for DSA. **That slice landed 2026-08-21: D-504 is closed.** It did read `index.xml`,
resolve shards by `RANGESTART` rather than expanding all 75, join the three blob families per update
by `RevisionId`, and adopt WiX DTF — extracting a shard once per run rather than materialising the
whole cab.

### The Ubuntu codename map was missing the current LTS — fixed 2026-07-29

`DistroReleases.Ubuntu` held **10** entries and stopped at `oracular` (24.10). Ubuntu's own
published list (`ubuntu.com/security/releases.json`) has **45**, so **35 were missing** — including
**`resolute`, 26.04 LTS**, plus `plucky`/`questing`/`stonking` and the interim series
`disco`/`eoan`/`groovy`/`hirsute`/`impish` that the usn-db still ships notices for.

The fallback meant nothing was dropped, so nothing failed — every fix statement for the current LTS
was simply filed under `ubuntu:resolute` instead of `ubuntu:26.04`, off the `ubuntu:<version>`
convention Phase 6 matches assets on. Proven red-first against real USN data:

```
Expected: ["ubuntu:22.04", "ubuntu:24.04", "ubuntu:26.04"]
Actual:   ["ubuntu:22.04", "ubuntu:24.04", "ubuntu:resolute"]
```

The map is now transcribed from Ubuntu's published list rather than recalled.

> **This label is part of row identity, so keeping it current is not cosmetic.**
> `advisory_affects` is unique on `(advisory_id, package_name, ecosystem, platform)`. Once content
> has been ingested, correcting a codename makes the next sync **INSERT a second row** rather than
> update the first. Adding a series before its first advisory lands is free; afterwards it is a data
> migration. Nothing has ingested yet — which is the reason this was fixed now rather than deferred
> to Phase 6.

### Also recorded: incrementality is emitted but never consumed

**No connector reads `state.Cursor`.** Every `Parse` computes a cursor and `ContentSyncService`
persists it (advancing on success, holding on failure), but no `SyncAsync` ever sends it back to the
feed. Refresh is therefore **idempotent but not incremental** — each run re-fetches the same window.
`NvdConnector`'s doc comment claimed "Incremental via `lastModStartDate`"; that claim was false and
has been corrected in place. **NVD pagination is also unimplemented** (`startIndex`/`totalResults`
never read), so a multi-page response is silently truncated to page 1 — a second silent-truncation
path. Exit criterion (b) stays unticked because of this, not merely for want of a test.

### One question a fixture must not settle

Every NVD record with no `metrics` at all, in the 300-CVE window sampled, was a **Rejected** CVE.
`Parse` ingests it as an advisory regardless of `vulnStatus`. Whether a rejected CVE should become an
advisory row is a real question and is **deliberately not answered by a test fixture** — see
`tests/PatchManagement.Content.Tests/Samples/PROVENANCE.md`.

### The store guarantees were shown capable of failing — 2026-08-16

Criteria (c)–(f) all passed first time, which by this project's rule means they had to be
*demonstrated* red before they could be trusted — the same standard applied to EPSS in parse slice 1
and to the `USN-` prefixing in slice 2. Each mutation below models a mistake an ordinary edit could
introduce, rather than blinding the test; each was confirmed present via `scripts/mutation-guard.ps1`
and reverted the same way.

| Mutation | Where | Result |
|---|---|---|
| Provenance merge → `provenance = EXCLUDED.provenance` (plain overwrite) | `ContentStore.UpsertAdvisoryAsync` | **1 red** — `A_publisher_resync_replaces_only_its_own_provenance_entry`, with `Collection: ["nvd"] / Not found: "kev"`. An NVD refresh had erased KEV's attribution |
| Publisher upsert also writes `kev_listed` / `epss_score` from `EXCLUDED` | `ContentStore.UpsertAdvisoryAsync` | **1 red** — `A_publisher_resync_does_not_reset_an_applied_overlay`. This is the exact edit the method's own NOTE warns against, and nothing but that column list prevents it |
| Two-pass patch/edge loop collapsed into one | `ContentSyncService.RunAsync` | **1 red** — `An_edge_resolves_when_the_superseded_patch_appears_later_in_the_same_batch`. The fixture orders the superseding patch first precisely so a one-pass implementation cannot pass |
| Affects `DO UPDATE` → `DO NOTHING` | `ContentStore.UpsertAffectAsync` | **1 red** — `A_fix_statement_with_no_platform_is_updated_rather_than_duplicated` |

Each mutation turned **exactly one** test red and left the other 27 green, so the suite localises a
regression rather than merely detecting one.

## Phase 5 deferrals — every one has a named owner and a gate

`DIFFERENTIATORS.md` forbids deferring without a named owner. Each row states what the owner
inherits and what it cannot claim until then.

| ID | Deferred | Owner | Gate — what cannot be claimed until it lands |
|----|----------|-------|----------------------------------------------|
| **D-501** | `ContentPostgresFixture` duplicates the shape of `PatchManagement.IntegrationTests.PostgresFixture` | **Phase 6** — the next phase to add a DB-backed suite | Two ephemeral-database fixtures coexist. Neither can simply consume the other: `TestSupport` is documented as referencing Contracts ONLY (a Persistence reference there would put EF in every consumer's output), and referencing the sibling test project would drag the API host in. A third consumer is the point at which the shared home has to be built rather than argued about |
| **D-502** | A KEV sync that records **"evaluated and absent"** | **Phase 7** — the consumer that would be misled | `advisories.kev_listed` is three-valued by design (NULL = not evaluated, false = evaluated and absent, true = listed) and `ContentCatalogueTests` pins that contract, but **the ingestion path can only ever write `true`**. After a complete KEV sync every CVE that is not known-exploited is still NULL, indistinguishable from a catalogue where KEV never ran. Phase 7 **cannot treat NULL as "not exploited"** until a sweep marks the complement — which needs a decision about what the complement means for a partial or failed run, since a KEV that fetched half its list must not mark the other half absent. Pinned by `A_kev_sync_cannot_currently_record_evaluated_and_absent` |
| ~~**D-504**~~ | **CLOSED 2026-08-21.** `wsusscn2` rewrite against the real cab format — the extractor now reads `index.xml`, resolves shards by `RANGESTART` and extracts through the vendored WiX DTF reader (ADR 0020, first consumer); the parser joins the graph to `c/`, `x/` and `l/en/` blobs by `RevisionId` | **Phase 5 — done** | Gate lifted. The Windows applicability engine ingests real patches and the Windows half of the HARD-PROBLEMS #4 supersedence DAG is present. Proven by `Wsusscn2ParseTests` over a captured slice AND `Wsusscn2CatalogTests` against the real 658 MB cab — the extractor's first successful run |
| **D-503** | Cycle detection over `patch_supersedence` | **Phase 6** — HARD-PROBLEMS #4 assigns cycle-breaking to assessment | `ck_patch_supersedence_no_self_loop` and the store's `older.id <> newer.id` filter catch a **1-cycle only**. A 2-cycle (A supersedes B, B supersedes A) inserts cleanly, and the effective-head walk does not terminate on it. Phase 5 deliberately does not reject it — a real feed can contradict itself and good content must not be refused over it — so **Phase 6's effective-head resolution cannot be claimed until it terminates on a cyclic graph**. Pinned by `A_two_patch_cycle_is_accepted_today_and_the_graph_is_not_provably_acyclic`, and the test helper's own walk is depth-capped for exactly this reason |

## ⚠ Scope: what has NOT been done

- **No connector has ever run end-to-end against its live feed.** `nvd`, `kev`, `epss` and `usn` are
  now proven against **real captured payloads** (`Samples/PROVENANCE.md`), as are `rhsa`, `msrc` and
  `dsa` since 2026-08-21 — a statement about the parser *and* about the shape the feed really serves.
  The HTTP fetch path itself remains unexercised for all of them. **`wsusscn2` is no longer among
  them**: its reader runs against the real cab in `Wsusscn2CatalogTests`, which makes it the one feed
  whose transport IS proven. The distinction Phase 3 records for WinRM still applies to the rest.
- **One USN branch is unreachable from real data and is left untested rather than faked.** All 7,678
  notices in the live usn-db carry at least one CVE, so `SourceMetadataJson == null` cannot be
  exercised by a capture. Likewise every codename in the database now maps, so the
  `ubuntu:<codename>` fallback is unreachable too — it remains for series that do not exist yet.
- ~~**`wsusscn2.cab` has never been expanded.**~~ **Done 2026-08-21.** `ExpandCabPackageSource` is
  replaced by `DtfWsusCatalogSource`, which has now run against the real 658 MB cab. It still throws
  `PlatformNotSupportedException` off Windows, and deliberately so: WiX DTF P/Invokes `cabinet.dll`
  and has no managed decompressor, so it is not the cross-platform answer this bullet assumed — an
  explicit refusal beats a `DllNotFoundException` from inside a P/Invoke.
- **Nothing invokes `ContentSyncService`.** There is no Hangfire job, no endpoint and no scheduler,
  so the shipped host can discover the module but cannot start a sync. Same shape as the Phase 2
  rotation trigger, whose owner is **Phase 11** — and this needs the same decision.
- **NVD affected-version ranges** (`advisory_ranges`) and **native Rocky/Alma errata** (RLSA/ALSA)
  are deferred. Both are additive and neither changes the frozen five.
