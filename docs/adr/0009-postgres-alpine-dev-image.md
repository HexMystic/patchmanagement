# 9. Dev Postgres image = postgres:16-alpine (musl/glibc collation parity gap)

- **Status:** Accepted (dev-only; revisit before production — see Consequences)
- **Date:** 2026-07-24

## Context
During Phase 0 setup, Docker Hub's CloudFront CDN persistently failed to serve the
Debian-based `postgres:16` image's large layers (~40+ `httpReadSeeker ... EOF`
failures across the session), while `redis:7` and all five lab distro base images
pulled cleanly. This blocked bringing the root product-infra stack up, which Phase 1
needs for migrations and the RLS isolation test.

`postgres:16-alpine` has much smaller layers and pulls reliably past the flaky CDN
edge.

## Decision
Use **`postgres:16-alpine` as the local development image** in the root
`docker-compose.yml`, to unblock Phase 1. This is a **dev-environment choice**, not a
production decision.

## Consequences — KNOWN DEV/PROD PARITY GAP (must be resolved before prod)
- **libc collation differs between variants.** The Alpine image uses **musl libc**;
  the Debian `postgres:16` image uses **glibc**. Their locale/collation
  implementations sort text differently, which changes:
  - **`ORDER BY` results** on text columns (different sort order),
  - **B-tree index ordering** on text/`varchar` keys, and therefore
  - the physical validity of an index if a data directory is moved between variants
    (an index built under one collation is **not** valid under the other).
- **Implications we accept for now:** fine for functional dev and Phase 1 contract
  work. **Not** acceptable for: performance testing, migration/`pg_upgrade` rehearsals
  against prod, or production packaging.
- **Required action before those:** **pin the production variant (Debian
  `postgres:16`, glibc) and revert the dev image to match**, so dev and prod share one
  collation. Recorded here as an explicit **dev/prod parity gap** and mirrored in
  `docs/ROADMAP.md` (Session Log) so it is not forgotten.
- Consider standardizing on an ICU collation (`LOCALE_PROVIDER=icu`) later to make
  ordering independent of the host libc — tracked as a follow-up, not done now.

## Rejected
- **Keep `postgres:16`, wait out the CDN** — indefinite block on Phase 1.
- **Silently switch to Alpine with no record** — hides a real correctness/parity gap a
  reviewer (or a future prod incident) would later hit.
