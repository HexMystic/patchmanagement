# 19. The content vocabulary admits a generic third-party application category

- **Status:** Accepted
- **Date:** 2026-08-20
- **Relates to:** CLAUDE.md §4.5 (frozen contracts), NEVER #6, HARD-PROBLEMS #3 (version
  comparison), [ADR 0010](0010-global-content-catalogue.md), [ADR 0011](0011-fixed-version-raw-as-sourced.md)
- **Applies to:** `advisories.source`, `patches.source`, `content_sources.kind`,
  `advisory_affects.ecosystem`, and — by construction, see Consequences — `advisories.cvss_source`
- **Gate:** decided **before Phase 6**, as ROADMAP Phase 16 required. Implementation is Phase 16,
  gated on Phase 6 completion.

## Context

The 2026-08-18 repo audit found that **every content feed on the roadmap is an OS-vendor feed** —
NVD, KEV, EPSS, USN, DSA, RHSA, MSRC and wsusscn2 all answer "which *operating-system* updates are
missing". Nothing in the product patches a third-party application. ROADMAP's "The market gap"
section records why that matters commercially; this ADR decides only the **vocabulary** question,
which is the part that is expensive to defer.

The Phase-1 vocabulary is frozen and OS-shaped. A third-party application fits none of it:

| Frozen CHECK | Values before this ADR | Why an application has no row |
|---|---|---|
| `advisories.source` | nvd, usn, rhsa, msrc, dsa | no vendor-advisory source for an application |
| `patches.source` | usn, rhsa, msrc, wsusscn2, dsa | no source for an application installer |
| `content_sources.kind` | nvd, kev, epss, usn, rhsa, msrc, wsusscn2, dsa | no feed kind to register one under |
| `advisory_affects.ecosystem` | deb, rpm, windows | a Chrome MSI is not a dpkg package, not an rpm, and not a Windows build threshold |

The deadline is structural, not commercial. **Phase 6 freezes correlation and version comparison
around three OS ecosystems, and Phase 8 builds deployment around OS-package installers.** Taking
this decision after either is a schema migration plus a rewrite of the comparator layer; taking it
now is five CHECK edits, five JSON-schema enum edits and one additive migration.

`DIFFERENTIATORS.md`'s cross-cutting rule states the general form: *every field a later phase cannot
cheaply add must exist in the contract before that phase starts.*

## Decision

**Third-party application patching is in scope for the product**, at the schema level, now.
Implementation is deferred to Phase 16 and gated on Phase 6 completion.

The frozen vocabulary is widened by **exactly two generic values**:

- **`app`** — the fourth `advisory_affects.ecosystem`. It names *the ecosystem*, not the vendor.
- **`vendor`** — added to `advisories.source`, `patches.source` and `content_sources.kind`. It names
  *a third-party application vendor as a publisher*, not any particular one.

**No vendor is enumerated.** `chrome`, `adobe`, `java`, `zoom` and the rest are **not** vocabulary
values, and adding them would be a mistake: the CHECK lists would then need editing — a NEVER #6
change — every time the catalogue covered one more application, which is precisely the coupling this
ADR exists to remove. Vendor identity is carried by columns that are already free-form:

| What identifies the vendor | Column | Already unique on |
|---|---|---|
| the feed | `content_sources.instance` | `(kind, instance)` |
| the affected product | `advisory_affects.package_name` | `(advisory_id, package_name, ecosystem, platform)` |
| the advisory | `advisories.external_id` | `(source, external_id)` |
| the installer | `patches.vendor_id` | `(source, vendor_id)` |

`content_sources` is the clearest case: `(kind, instance)` is *already* the upsert key and
`Several_feeds_of_the_same_kind_can_be_registered` already pins it, so `kind = 'vendor'` with
`instance = 'google-chrome'` alongside `instance = 'adobe-reader'` needs no new machinery at all.

### Why one generic ecosystem rather than several

`msi`, `exe`, `pkg` and `dmg` were considered and rejected. Those are **installer formats**, not
ecosystems — the same Chrome release ships as an MSI and a PKG, and would then need two ecosystem
values for one comparison rule. HARD-PROBLEMS #3 defines an ecosystem by its **version-comparison
semantics**, and every third-party application shares the property that distinguishes it from the
three OS ecosystems: its version string follows the *vendor's own* convention, with no `epoch:`, no
`-release` and no guaranteed dotted-quad. That is one comparator problem, so it is one ecosystem.

If a specific vendor's versioning later proves genuinely incomparable under the `app` comparator,
that is the moment to argue for a fifth ecosystem — with a comparator in hand, per HARD-PROBLEMS #3,
which holds that a fourth ecosystem needs a comparator before it needs a row.

## Consequences

**A fifth constraint moves, by construction.** `ck_advisories_cvss_source` is defined in
`AppDbContext` as `InList("cvss_source", ContentSourceKinds)` — it *reads* the feed-kind list rather
than repeating it. Widening `content_sources.kind` therefore widens `cvss_source` too. This is
intended and correct: a vendor advisory carrying its own CVSS score must be able to record where the
score came from, and the existing comment on `ContentSourceKinds` already states that `cvss_source`
uses the wide feed list deliberately, for provenance semantics. It is called out here because **five**
constraints change, not the four the gate named.

**Phase 16 must namespace `external_id` and `vendor_id`.** `UNIQUE (source, external_id)` and
`UNIQUE (source, vendor_id)` previously got vendor separation for free, because each source was a
single publisher. With every application vendor sharing `source = 'vendor'`, two vendors could
collide on a plausible identifier (`2026-01`, `SA-001`). Phase 16 qualifies the identifier per
vendor; the constraint is unchanged, the *convention* for filling it is not yet decided, and this is
the one Phase 16 design task this ADR creates rather than removes.

**An `app` comparator becomes a Phase 6 exit criterion, not a Phase 16 surprise.** Phase 6 must build
its comparator layer **ecosystem-extensible** — resolving `IVersionComparator` by ecosystem, with an
unknown ecosystem failing loudly rather than silently falling back to string compare. See
`docs/phases/phase-6.md`. Phase 6 is **not** required to *implement* the `app` comparator; it is
required not to make implementing one a rewrite.

**Nothing is claimed to work.** This ADR admits values. No connector produces them, no comparator
consumes them, and no assessment path understands them. Phase 5's hard-won rule applies with full
force: a feed that returns an empty batch and reports `ok` is worse than one that fails loudly. The
vocabulary being open is not evidence that anything is ingested.

**Migration safety.** `20260820144646_ThirdPartyApplicationVocabulary` is additive only: every list
is its former self plus one value, so every row satisfying the old CHECK satisfies the new one. No
column is added, dropped or retyped, and no data is rewritten. Verified by migrating a database
seeded with old-vocabulary rows across all four tables and checksumming each before and after —
identical. `Down` restores the original five constraints and was executed successfully; note that
`Down` will fail, correctly, if any row using the new values exists by then.

## Alternatives rejected

- **"OS-only v1, applications in v2."** A defensible product position, and the ROADMAP audit
  explicitly allowed it. Rejected because the *vocabulary* cost is asymmetric: admitting two generic
  values now costs one additive migration, while retrofitting them after Phase 6 costs a comparator
  rewrite. Deciding "in scope" at the schema level commits no build capacity — Phase 16 remains
  unscheduled — so this buys the option cheaply rather than buying the feature.
- **A separate `applications` table tree.** Duplicates the provenance merge, the supersedence DAG and
  the overlay rules that Phase 5 already proved against real Postgres, and would need its own
  assessment path. The catalogue's shape was never OS-specific; only its vocabulary was.
- **Dropping the CHECK constraints in favour of application-level validation.** Rejected outright.
  The CHECKs are what would have caught the invented-envelope connector defects at ingest, and a
  constraint that admits anything is not a contract.
