# 22. Debian DSA content is sourced from salsa.debian.org's raw plain-text list

- **Status:** Accepted
- **Date:** 2026-08-20
- **Relates to:** HARD-PROBLEMS #2 (backport detection), #3 (version comparison), **#8 (honest state
  model)**, [ADR 0011](0011-fixed-version-raw-as-sourced.md) (`fixed_version` stored raw),
  [ADR 0016](0016-single-process-vault.md) (the "reports success while untrue" doctrine)
- **Applies to:** `DebianDsaConnector`, the `dsa` feed, Phase 5 exit criterion (a)
- **Unblocks:** the DSA connector slice. Does **not** implement it — no connector, parser, sample or
  test is written by this ADR.

## Context

`DebianDsaConnector.DefaultEndpoint` points at
`security-tracker.debian.org/tracker/data/dsa.json`, which **404s**. On 2026-07-29 every plausible
Debian source was probed and the result recorded (`docs/phases/phase-5.md`, on `phase/5-content`):

| Source | Result | DSA ids? | Per-suite fixed versions? |
|---|---|---|---|
| `tracker/data/dsa.json` *(the connector's endpoint)* | **404** | — | — |
| `tracker/data/DSA/list` | **404** | — | — |
| `tracker/data/json` | 200, **80 MB**, package→CVE→releases | **none — the string `DSA-` does not appear** | per-CVE only |
| `salsa…/security-tracker/raw/master/data/DSA/list` | 200, 1.1 MB, **plain text** | ✅ 6,466 | ✅ |
| `www.debian.org/security/dsa-long.rdf` | 200, 28 KB | ✅ but only **31** items | ❌ |
| `www.debian.org/security/oval/oval-definitions-*.xml` | **403** | — | — |

That session deferred the choice deliberately, in these words: *"deciding whether a
`salsa.debian.org` raw-git URL is an acceptable production dependency … is a **data-source
decision, not a parse test**"*. This ADR answers it.

Debian is not optional. HARD-PROBLEMS #2/#3 require it, the lab fleet includes a Debian 12 box, and
`dsa` is already in the frozen vocabulary (`advisories.source`, `patches.source`,
`content_sources.kind`). Rejecting the only usable source means dropping Debian support from Phase 5
— a larger decision than this one, and not the one being taken.

### Stating the premise precisely

It is tempting to write "Debian publishes no structured advisory feed". That is **stronger than the
evidence**, and a future reader could disprove it with one `curl`.

What is actually true: Debian **does** serve structured JSON at `tracker/data/json`. It was rejected
for a specific recorded reason — *"It carries no DSA identifiers, so advisories would have no
`external_id` — breaking the frozen `advisories(source, external_id)` uniqueness — and it drops the
advisory-level fixed version HARD-PROBLEMS #2 needs for backport detection."* And the OVAL endpoint
returned **403**, which is a block, not an absence.

So the accurate claim is narrower and more useful: **no Debian source that carries DSA identifiers
*and* per-suite fixed versions is available in a structured format today.** That phrasing yields two
concrete re-open triggers instead of an absolute — see "When to revisit" below.

## Decision

**Accept `https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list`
as the Debian advisory source.** It is maintained by Debian's own security team — legitimacy is not
in question — and it is the only form carrying both DSA identity and per-suite fixed versions. The
format is line-oriented text:

```
[28 Jul 2026] DSA-6402-1 hplip - security update
	{CVE-2026-8631 CVE-2026-8632}
	[trixie] - hplip 3.22.10+dfsg0-8.1+deb13u1
```

**Provenance still cites the canonical Debian URL.** The fetch targets salsa, but each advisory's
`ProvenanceEntry.Url` continues to point at `security-tracker.debian.org/tracker/DSA-xxxx`, which is
the stable human-facing reference. Transport and citation are separate concerns, and an operator
auditing a finding should land on Debian's own tracker page rather than a git forge raw URL.

## The risk being accepted: stability, not legitimacy

This must not be recorded as equivalent to the other seven sources, because it is not.

| | The other seven | `dsa` |
|---|---|---|
| Form | versioned API or structured feed | **plain text** |
| Hosting | vendor's advisory infrastructure | **a git forge (GitLab), raw file endpoint** |
| Contract | documented schema / media type | **none — file layout is a convention** |
| Change signalling | API version, schema | **none: a commit changes it silently** |

A raw-git URL has no publisher stability contract. Column widths, tab-vs-space, suite tags and the
edge-case markers (`<not-affected>` ×52, `<end-of-life>` ×4, `<unfixed>` ×2, 12 suites back to
`woody`) can all change in a commit, with no deprecation window and no version to pin. **This is the
weakest source in the product, and it is accepted knowingly.**

## Mitigations

### (a) Fail loudly on drift — never an empty batch reported as `ok`

**This is the binding requirement, and it exists because the project has already shipped this exact
defect twice.**

- **`rhsa`** — the real body is a JSON array; `Parse` reads `root.Array("advisories")`, and
  `JsonHelpers.Array` returns `[]` for a non-object receiver. Result: *"an **empty batch and a status
  of `ok`**"*, cursor advanced. Recorded as *"the dangerous one … An operator sees a green sync and
  an empty catalogue — reports success while untrue."*
- **`wsusscn2`** — the first filter is `if (kb is empty && isSoftware != "true") continue;`, and
  against the real catalogue `KBArticleID` never exists and `IsSoftware` is never `"true"`, so **all
  136,965 updates are skipped**. `ContentSyncService` then records `status = 'ok'`, 0 patches, and
  advances the cursor.

Both are instances of the doctrine in [ADR 0016](0016-single-process-vault.md): *"treat every success
signal in this subsystem as guilty until proven … ask what a caller does on `true` — here they stop,
and do not re-run — and who benefits if it is wrong."* And of HARD-PROBLEMS #8: collapsing "couldn't
check" into "fine" is *"the cardinal sin of a security product"*.

A text parser is **more** exposed to this than a JSON one, because a format change does not throw —
it simply stops matching, and a regex that matches nothing yields zero advisories and no error. So
the DSA slice must satisfy:

1. **A parse yielding zero advisories from a non-empty document is a FAILURE**, not an empty
   success. The sync must record `failed` with an error naming what did not match.
2. **The concrete hole to close:** `ContentSyncServiceTests` currently asserts that a *good* batch
   reports the counts it wrote, but **nothing forbids a zero-count `ok`**. That gap is what let
   `rhsa` and `wsusscn2` through. The slice must add the negative assertion.
3. **Shape invariants are asserted, not assumed** — the advisory count is within a sane band of the
   6,466 observed, and the `[suite] - package version` line shape still matches.

### (b) Red-first, against real captured payloads only

`tests/PatchManagement.Content.Tests/Samples/PROVENANCE.md` states the standing discipline:

> Every file here is a **real payload captured from the live feed** … The two fixtures that
> previously sat here were **hand-written**, in the same commit as the parsers they fed — fictional
> vendors (`FooCorp`/`libfoo`), fictional CVE ids, and containing *only* the keys each parser reads.
> A parser asserted against a fixture written to that parser proves self-consistency and nothing
> else. Both were deleted. **Do not reintroduce a hand-authored payload here; if a feed cannot be
> captured, the connector stays untested and unticked.**

`dsa` has **no captured sample today** — nor do `rhsa`, `msrc` or `wsusscn2`. Four feeds, zero
captures. The entry condition is already written: *"Rewriting each against a real captured payload is
the entry condition for its slice."*

For DSA specifically: capture the real list, and if truncating for size, follow the KEV/USN
precedent — retain whole records field-for-field, declare the truncation in `PROVENANCE.md`, and do
not "correct" real values to make the file self-consistent. The edge-case markers are the point of
the capture; a tidy sample would prove nothing.

### (c) Drift detection — the sync is the detector; Phase 11 owns the alarm

Given (a), **every sync is a drift check**. A fail-loud parser writes `last_status = 'failed'` and
`last_error` to the feed's `content_sources` row, and the cursor holds rather than advancing. No new
monitoring mechanism is introduced, and none needs to be: the detector is the thing already running.

**Owner: Phase 11 (scheduling, notifications, reporting)** — it owns surfacing a failed feed row to
an operator, and it already owns the equivalent gap for the Phase 2 rotation trigger.

**What this honestly does not cover, stated rather than implied:**

- Nothing detects drift while no sync runs — and **nothing invokes `ContentSyncService` at all
  today**: no Hangfire job, no endpoint, no scheduler. The detector is **latent until Phase 11
  exists**. Until then, drift is found by whoever next runs a sync by hand.
- Nothing watches for *semantic* drift that still parses — e.g. Debian moving the file's default
  branch from `master`, which would 404 (caught), versus silently changing what a suite tag means
  (not caught).
- A separate scheduled shape-canary was considered and **not** adopted: it would be a second
  network-dependent moving part, with no CI in this repo to run it, duplicating what a fail-loud
  sync already does.

## Known gaps for the DSA slice — named, not solved

- **The cursor contract breaks.** `DebianDsaConnector` cursors on the maximum `timestamp` field. The
  text list has **no timestamp** — only `[28 Jul 2026]` date strings. Exit criterion (b)
  (incrementality) inherits this, and a raw-git URL has no conditional-GET story either. The slice
  must restate the cursor contract, not paper over it.
- **The codename map is a stated starting point.** `DistroReleases.Debian` covers `stretch`…`trixie`;
  the list carries `woody`, `sarge`, `etch`, `lenny`, `squeeze`, `wheezy`, `jessie`, and `forky` is
  coming. Unmapped suites fall through to `debian:<codename>`. Pinned by `DistroReleasesTests`.
- **`DebianDsaConnector`'s class doc still reads as though the connector works.** Unlike
  `Wsusscn2Connector`, it carries no defect banner even though its endpoint 404s. The slice should
  annotate it the same way. Not done here — that file lives on `phase/5-content`.
- **`PROVENANCE.md` is partly stale**: it says `wsusscn2.cab` "has never been executed against",
  which stopped being true on 2026-08-16 when the cab was opened.

## When to revisit

Two concrete triggers, either of which makes a better source available:

1. **The OVAL endpoint becomes reachable.** `oval-definitions-*.xml` currently returns **403**, which
   may be user-agent or infrastructure blocking rather than absence. Structured, versioned, and
   carrying fixed versions — it would be strictly better than parsing text.
2. **Debian publishes DSA-identified structured data**, closing the `external_id` gap that
   disqualified `tracker/data/json`.

## Rejected alternatives

- **The CVE-keyed JSON (`tracker/data/json`).** Structured and 200, but no DSA identifiers means no
  `external_id`, which breaks the frozen `advisories(source, external_id)` uniqueness, and it drops
  the advisory-level fixed version HARD-PROBLEMS #2 needs. Considered and rejected on 2026-07-29;
  re-affirmed here.
- **`dsa-long.rdf`.** Structured and small, but **31 items** against 6,466 advisories, and no fixed
  versions. It is a news feed, not a catalogue.
- **Dropping Debian support.** The honest alternative to accepting a fragile source, and a bigger
  call than this one: it would remove a lab-fleet distro, contradict HARD-PROBLEMS #2/#3, and leave
  `dsa` in the frozen vocabulary with nothing behind it.
- **Vendoring a snapshot of the list into the repo** to escape the stability risk. Rejected: a
  security catalogue that is stale by construction is worse than a fresh one that occasionally
  breaks loudly. Fragility that fails visibly beats staleness that fails silently — which is the
  whole argument of mitigation (a).
