# 23. Incrementality is per-feed, and the cursor carries HTTP validators as well as a bookmark

- **Status:** Accepted
- **Date:** 2026-08-25
- **Relates to:** [ADR 0022](0022-debian-dsa-source.md) (which named this as an open gap),
  [ADR 0008](0008-windows-content-source.md) (wsusscn2 ingestion must be incremental),
  [ADR 0016](0016-single-process-vault.md) (the "reports success while untrue" doctrine),
  [ADR 0018](0018-content-contract-surface.md) (the content contract split)
- **Applies to:** all eight content connectors, `IHttpContentFetcher`, `content_sources.cursor`,
  Phase 5 exit criterion **(b)**
- **Supersedes nothing.** It restates a contract ADR 0022 flagged as broken.

## Context

Phase 5 criterion (b) reads *"refresh is **incremental** — the cursor advances on success and holds
on failure"*. Half of it was built: every connector computed a cursor, `ContentSyncService` persisted
it, advanced it on success and held it on failure, and two tests pinned that behaviour.

The other half was not. **No connector ever read `state.Cursor`.** `docs/phases/phase-5.md` recorded
it plainly — *"incrementality is emitted but never consumed … each run re-fetches the same window"* —
and `NvdConnector`'s doc comment had claimed the opposite until that claim was struck.

ADR 0022 named the reason a single fix would not do:

> **The cursor contract breaks.** … Exit criterion (b) (incrementality) inherits this, and a raw-git
> URL has no conditional-GET story either. **The slice must restate the cursor contract, not paper
> over it.**

### The premise, stated precisely

It is tempting to write "wire the cursor into the request" as if that were one job eight times. It is
not. **Four of the eight feeds serve a whole file with no filter parameter.** For those, appending a
`?since=` would be a request written against a shape the server does not implement — the exact defect
this module has already had to delete three times (`rhsa`'s invented `root.advisories[]`, `msrc`'s
invented `remediations[]`, `dsa`'s invented JSON root map). Repeating it here would be worse than
leaving criterion (b) unticked, because it would *look* incremental.

## Decision

**Incrementality is chosen per feed, from what the source actually implements.** Four mechanisms:

| Feed | Mechanism | What reaches the source | Basis |
|---|---|---|---|
| `nvd` | server-side window | `lastModStartDate` + `lastModEndDate` | **probed 2026-08-25** — see below; both required together |
| `rhsa` | server-side window | `after=YYYY-MM-DD` | **probed 2026-08-25** — see below |
| `msrc` | request selection | the cursor picks *which month documents* are fetched from the index | the index lists 191 months; captured in `msrc.updates.sample.json` |
| `kev` | conditional GET | `If-None-Match` / `If-Modified-Since` | whole file, no filter parameter |
| `usn` | conditional GET | `If-None-Match` / `If-Modified-Since` | whole file, no filter parameter; body is 260 MB |
| `epss` | client-side cutoff | *nothing* — the model date bounds what is written | scores are republished whole, daily |
| `dsa` | client-side cutoff | *nothing* — the full DSA id bounds the parse | ADR 0022: raw-git, no filter and no conditional-GET story |
| `wsusscn2` | local comparison | *nothing* — no network; `PackageId` gates the walk | ADR 0008; the cab is fetched out-of-band |

**`epss` and `dsa` save database work and parse work, not bandwidth. That is stated rather than
dressed up.** Calling them "incremental" without that sentence would be the same species of claim as
the NVD doc comment this slice exists to make true.

### The cursor contract, restated

`content_sources.cursor` now carries up to two things, encoded by `FeedCursor`:

- **the semantic bookmark** — what `Parse` computes, and what a feed's own filter parameter is built
  from: an NVD `lastModified`, a KEV `catalogVersion`, an MSRC month id, a full DSA id, a wsusscn2
  `PackageId`;
- **HTTP validators** — `ETag` and `Last-Modified`, for the conditional-GET feeds only.

**With no validators the encoded form IS the bare semantic string, byte for byte.** Six of the eight
feeds therefore persist exactly the value they persisted before this ADR, every cursor already in the
database reads back unchanged, and no migration is required. Only `kev` and `usn` gain the JSON form.
`FeedCursorTests` pins that guarantee as an equality, not a shape.

`FeedCursor.Read` never throws. An undecodable cursor degrades to semantic-only, costing one full
fetch. Throwing would wedge the feed permanently: the failure path holds the cursor it could not
read, so every subsequent run would fail identically with no path to recovery.

### A 304 is evidence, not an empty read

This module throws when a parse yields nothing, because an empty catalogue reported as `ok` is its
recurring hazard (ADR 0022 mitigation (a)). A 304 is the opposite case and is **explicitly permitted**
to write nothing: the server was asked and asserted that nothing changed. The same reasoning covers
`dsa` stopping at its cursor with nothing above it, and `wsusscn2` finding an unchanged `PackageId`
— in both, absence was established rather than inferred. Each of those paths is narrowly carved out
of the fail-loud guard rather than weakening it, and each carves at the specific condition that
proves the absence.

### `IHttpContentFetcher` gains one method

`GetStringConditionalAsync(uri, etag, lastModified, ct)` returns `ConditionalFetch`, which is either
a body plus fresh validators or `NotModified`. Passing null validators degrades to an ordinary GET,
which is what a first run does.

The seam stays in the module rather than moving to Contracts — ADR 0018's split is unchanged, and
`ContentContractSurfaceTests` still asserts it. `content_sources.cursor` is a `text` column and its
type does not change, so **no frozen contract is touched** (CLAUDE.md NEVER #6): not the schema, not
RLS, not OpenAPI, not the JSON schemas, not the state machine.

## Consequences

- Criterion (b) is satisfiable and, for the first time, falsifiable: `IncrementalSyncTests` asserts
  through the **outgoing request**, because a connector that reads a cursor and discards it returns a
  batch indistinguishable from a correct one.
- `usn` is the largest single win — a 304 replaces a 260 MB transfer.
- `nvd` pagination is fixed in the same slice. It had to be: a cursor-narrowed window sitting on top
  of a fetch that silently truncated to page 1 would have made the truncation *harder* to notice, not
  easier, because the window would explain away the small result.
- Two feeds now carry a JSON cursor. Anything that reads `content_sources.cursor` for display must go
  through `FeedCursor`, not eyeball the column.

## The two outgoing parameters were probed against the live feeds — 2026-08-25

Both parameters this ADR puts on the wire were verified against the real endpoints, and **not merely
for a 200**: a parameter a server ignores also returns 200, and would leave every "incremental" run
silently fetching everything. The check is therefore that the result set actually narrows and that
every record respects the boundary.

**`nvd` — `lastModStartDate` + `lastModEndDate`**

| Request | Result |
|---|---|
| no window, `resultsPerPage=1` | 200, **`totalResults` = 382,390** (the whole catalogue) |
| `lastModStartDate=2026-08-20T00:00:00.000Z`, `lastModEndDate=2026-08-25T00:00:00.000Z` | 200, **`totalResults` = 3,758** |
| same window, 20 records inspected | every `lastModified` inside the window (min `2026-08-20T19:14:38.670`, max `2026-08-24T18:22:58.150`) |
| `lastModStartDate` **alone**, no end date | **404** |

The last row matters as much as the others: it confirms the pairing requirement is real, so
`Nvd_pairs_the_window_with_an_end_date` guards an actual failure rather than a supposed one. Sending
one bound without the other would 404 every incremental run after release. The timestamp format used
is exactly the one `NvdConnector.NvdInstant` emits — `yyyy-MM-ddTHH:mm:ss.fffZ`.

**`rhsa` — `after=YYYY-MM-DD`**

| Request | Result |
|---|---|
| no filter, `per_page=1000` | 200, 1,000 records, oldest `released_on` = `2026-07-27T12:14:45Z` |
| `after=2026-08-20`, `per_page=1000` | 200, **133 records**, oldest `released_on` = `2026-08-20T00:05:15Z` |

The filter narrows the set and no record predates the boundary. The oldest result falls **on** the
boundary day, which confirms the inclusive semantics `RhsaConnector.After` documents: dropping the
cursor's time half re-reads its own day, and the upserts are idempotent, so that is the safe rounding
direction.

## Known gaps — named, not solved

- **An `nvd` cursor older than NVD's 120-day window ceiling falls back to a full fetch.** Correct and
  expensive, rather than clamped-forward and silently lossy. Walking the gap in 120-day chunks is the
  obvious refinement and is deliberately not half-built here.
- **`kev` and `usn` depend on their hosts actually serving validators.** If a host serves none, the
  cursor degrades to semantic-only and every run transfers the whole body — the pre-ADR behaviour, so
  the failure mode is a lost optimisation, not a lost record.
- **`msrc` back-fill is not attempted.** A first run, or a cursor the index no longer carries, takes
  the newest month only. Re-ingesting 191 documents because one id moved would be a self-inflicted
  outage; a missing older month is visible in the catalogue, which is the recoverable direction.

## When to revisit

- If either vendor changes or retires its filter parameter. Both fail loudly rather than
  silently-wrong: NVD 404s a malformed window, and an unknown Red Hat parameter degrades to a full
  fetch, which is expensive and visible rather than quietly partial.
- If Debian ever serves the DSA list from a host with usable validators, `dsa` moves from the cutoff
  family to the conditional family and ADR 0022's "no conditional-GET story" note is superseded.
- If a feed's cursor ever needs a third component, that is the signal that `FeedCursor` should become
  a versioned envelope rather than gaining another optional property.
