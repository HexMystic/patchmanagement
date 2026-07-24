# 11. `fixed_version` and `platform` are stored raw-as-sourced; parsing belongs to the Phase 6 comparator

- **Status:** Accepted
- **Date:** 2026-07-24
- **Relates to:** HARD-PROBLEMS #2 (backport detection), #3 (version comparison)
- **Applies to:** `advisory_affects.fixed_version`, `advisory_affects.platform`

## Context

`advisory_affects` records "advisory X is fixed in version Y of package Z". The values
sources publish are ecosystem-specific and structurally different:

| Ecosystem | Example `fixed_version` | Structure |
|-----------|------------------------|-----------|
| Debian/Ubuntu | `3.0.2-0ubuntu1.16` | `[epoch:]upstream-revision`, tilde sorts *before* everything |
| RHEL/RPM | `0:1.2.3-4.el9_3` | `epoch:version-release`, **epoch dominates**, `rpmvercmp` tilde/caret rules |
| Windows | `10.0.19045.4046` | four-part build number — "patched" is a build threshold, not a package version |

There is a real temptation to normalize at ingest: split epoch/upstream/revision into
columns, or coerce everything to a comparable canonical form, so the database can answer
"is the installed version older than the fixed version?" with an index.

HARD-PROBLEMS #3 already establishes that comparison requires **per-ecosystem
comparators with exact native semantics** (`rpmvercmp` and `dpkg --compare-versions`
ported faithfully, numeric tuple compare for Windows builds) behind a common
`IVersionComparator`, covered by a conformance corpus drawn from real advisories — and
that a generic string/semver compare is wrong for all three.

A second, related question surfaced while designing the table: a single advisory
routinely states **different fixed versions for the same package and ecosystem**. One
USN covers every supported Ubuntu release (`openssl` fixed at `1.1.1f-1ubuntu2.22` on
20.04, `3.0.2-0ubuntu1.16` on 22.04, `3.0.13-0ubuntu3.1` on 24.04); one Debian DSA spans
bullseye and bookworm; one MSRC CVE spans Windows 10 21H2 / 11 23H2 / Server 2022, each
with its own KB and its own fixed build. So the row grain needs a column naming **which
release the fixed version applies to** — and that value is just as source-specific as the
version itself.

## Decision

**Store both `fixed_version` and `platform` exactly as the source publishes them.** No
parsing, no epoch/revision splitting, no canonicalization, no normalization at ingest.

```
fixed_version text NULL   -- '3.0.2-0ubuntu1.16', '0:1.2.3-4.el9_3', '10.0.19045.4046'
platform      text NULL   -- 'ubuntu:22.04', 'rhel:9', 'debian:12', 'windows:server-2022'
ecosystem     text NOT NULL CHECK (ecosystem IN ('deb','rpm','windows'))
```

`ecosystem` is the **only** interpreted field — it is the discriminator that tells the
Phase 6 comparator which native semantics to apply, and it is CHECK-constrained to the
three comparators HARD-PROBLEMS #3 defines.

**Interpretation is owned entirely by Phase 6's `IVersionComparator`** and its
conformance corpus. Phase 5 (ingestion) transcribes; Phase 6 compares.

### Scope: this table holds FIX STATEMENTS, not vulnerability ranges

`advisory_affects` answers *"which version fixes this, on which release?"*. It is fed by the
**applicability sources** — USN, RHSA/OVAL, Debian DSA, MSRC/wsusscn2 — which is exactly what
HARD-PROBLEMS #2 requires, and which explicitly **rejects** "CPE/NVD version ranges alone" as an
applicability basis because they are blind to backports.

**NVD's affected-version ranges are therefore out of scope for this table.** NVD does not publish
"fixed in V"; it publishes ranges (`versionStartIncluding` / `versionEndExcluding`), routinely
several per product per CVE — e.g. OpenSSL affected at `1.1.1 ≤ v < 1.1.1t` *and*
`3.0 ≤ v < 3.0.8`. This table has no range columns and cannot represent that, by design: NVD is
the **CVE overlay** (severity, CVSS, KEV/EPSS linkage — all of which live on `advisories`), not
the applicability engine (ADR 0008 makes the same split for Windows).

If Phase 5 later needs to persist NVD ranges — for a CPE-based fallback where no distro advisory
exists — that is an **additive `advisory_ranges` table owned by Phase 5**, with its own grain
(`introduced`/`fixed` bounds). It is not a change to this one, and it must not be smuggled in by
overloading `fixed_version`.

Both columns are **nullable, with no sentinel value**:
- `fixed_version` is NULL when the source states no fix is available yet (an advisory published
  before a fix ships — common for RHSA embargo windows and MSRC "no update available" entries).
- `platform` is NULL when the source states no release scope. This happens with **vendor-generic
  advisories** that name a product without enumerating releases, and with MSRC entries that map a
  CVE to a package without a per-build breakdown. Inventing `'unspecified'` would fabricate
  content, which is the dishonesty HARD-PROBLEMS #8 exists to prevent, applied to the content
  layer.

Because `platform` is nullable *and* part of the row's identity, the uniqueness
constraint must treat NULLs as equal:

```sql
ALTER TABLE advisory_affects ADD CONSTRAINT uq_advisory_affects
  UNIQUE NULLS NOT DISTINCT (advisory_id, package_name, ecosystem, platform);
```

`NULLS NOT DISTINCT` (PostgreSQL 15+; we run 16) is load-bearing: under default
NULL-distinct semantics two NULL-`platform` rows would both insert, silently breaking the
idempotent upsert that HARD-PROBLEMS #6 makes a design assumption. `fixed_version` stays
**payload, not key** — with `platform` in the key, each (advisory, package, ecosystem,
platform) has exactly one fix; if a source ever states two, that is a content conflict to
surface, not something to store twice.

## Consequences

- **The raw string is the auditable provenance artifact** — as last written. "What does
  USN-6789-1 say?" is answerable from the row verbatim, rather than "whatever our parser made of
  it in 2026," which would be unfalsifiable and unrecoverable. **Limit, stated honestly:** this
  table is upserted, so an in-place `fixed_version` correction overwrites the previous string and
  the row keeps no history. If Phase 5 or Phase 13 needs "what did it say *last month*", that is a
  retained raw payload (`advisories.raw_ref`) or an append-only content-history table — not an
  inference from this row.
- **A parser bug is recoverable.** Comparison happens at assessment time from the raw
  value, so fixing the comparator re-fixes every historical finding on the next
  assessment run. Under normalize-at-ingest, a wrong split silently corrupts stored data
  and requires a re-ingest of the entire corpus to repair.
- **No index-assisted version-range queries at the database.** Comparison runs in
  application code, per ecosystem. Accepted: correlation is already per-(package,
  ecosystem) — indexed — and the candidate set after that filter is small.
- **A derived `normalized_version` cache may be added later** as a performance
  optimization if profiling demands it. If added, it is **explicitly a cache**: rebuilt
  from the raw column, never the source of truth, never the only surviving copy.
- **`platform` values are not a controlled vocabulary.** They are raw, so `ubuntu:22.04`
  and `Ubuntu 22.04 LTS` from two sources will not match. Phase 6 owns mapping platform
  strings to host facts as part of correlation; if that mapping needs a lookup table, it
  is a Phase 6 table keyed on the raw value, not a rewrite of this column.

### Known limits of this grain, recorded rather than discovered later

- **`package_name` on Windows rows.** The column is `NOT NULL`, but Windows advisories name a
  *product/component*, not a package. Windows applicability comes from `wsusscn2` → `patches`
  (ADR 0008), so windows-ecosystem rows here are the exception rather than the rule; where they
  occur, `package_name` carries the product/component string as sourced. If that proves
  insufficient, the fix is a Phase 5 discriminator column, not overloading `platform`.
- **No `arch`.** Where a source states a different fixed version per architecture (rare for RHSA,
  which normally publishes one NEVR per release), those rows would collide on this key. Deferred:
  **Phase 5** owns adding `arch` to the grain if a real feed requires it. Recorded so the collision
  is recognised rather than debugged.
- **`ecosystem` is CHECK-constrained to `deb`/`rpm`/`windows`.** A fourth ecosystem needs a
  comparator (HARD-PROBLEMS #3) before it needs a row, so the constraint is the correct gate.

## Rejected

- **Parse into `epoch` / `upstream` / `revision` columns at ingest.** Puts per-ecosystem
  version semantics in Phase 5, the wrong layer, and duplicates logic Phase 6 must
  implement correctly anyway. Lossy and irreversible: a wrong split cannot be undone from
  the split result.
- **Canonicalize to a generic/semver form.** HARD-PROBLEMS #3 rejects generic semver as
  wrong for all three ecosystems; storing the canonical form only would bake that
  wrongness into the frozen contract.
- **Compare in SQL with a custom operator class.** Would need `rpmvercmp` and `dpkg`
  semantics as database functions — untestable against the .NET conformance corpus, and
  it moves correctness-critical logic out of the layer that has tests for it.
- **`platform NOT NULL` with an `'unspecified'` sentinel.** Reads as "the source said
  unspecified" when the truth is "the source said nothing" — fabricated content, and it
  would also mask the missing-platform case from anyone querying for it.
