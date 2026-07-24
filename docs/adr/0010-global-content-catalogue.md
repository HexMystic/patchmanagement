# 10. The content catalogue is global, not tenant-scoped

- **Status:** Accepted
- **Date:** 2026-07-24
- **Amends:** CLAUDE.md §4.1, `docs/phases/phase-1.md` (Multi-tenancy & Core tables)
- **Context:** the C1 resolution (`docs/ROADMAP.md`, `docs/reviews/phase-1-review.md`)

## Context

Phase 1's contract pulled forward five tables that hold vulnerability/patch content:
`content_sources`, `advisories`, `advisory_affects`, `patches`, `patch_supersedence`.

Both governing documents specified them as tenant-scoped:

- **CLAUDE.md §4.1** — "Every table carries `tenant_id`. PostgreSQL row-level security
  (RLS) is enforced at the database layer."
- **`phase-1.md`** — "Every table: `tenant_id uuid not null`", with `tenants` annotated
  as "the only non-tenant-scoped root table", and all five content tables listed in the
  core-tables table whose header reads "besides `tenant_id`, `id`, timestamps".

So this is a **deliberate amendment to the project constitution**, not a gap being
filled. It was raised and approved explicitly (CLAUDE.md NEVER #6) rather than decided
in passing.

The content in question is **public vendor data** — NVD CVEs, CISA KEV, EPSS scores,
Ubuntu USNs, RHSAs, MSRC CSAF, `wsusscn2.cab` applicability. It is byte-identical for
every tenant. Tenant-scoping it would mean:

- **N copies of the corpus** — the NVD alone is hundreds of thousands of records, and
  storage/ingest cost multiplies by tenant count for zero differentiation.
- **A per-tenant sync loop.** Phase 5's ingestion runs on Hangfire, off the HTTP path.
  Review **M6** establishes there is no tenant-context mechanism there, and the RLS
  policy fails closed — so a tenant-scoped content sync would either silently no-op or
  need a bespoke per-tenant scope factory before Phase 5 could write a single row.

## Decision

The five tables are **global**: no `tenant_id`, no RLS, no `tenant_isolation` policy.

Access is split by role rather than by row:

| Role | Content catalogue | Rationale |
|------|-------------------|-----------|
| `patchmgmt_app` (request path) | **SELECT only** | a request-path bug must not be able to rewrite content for every tenant at once |
| `patchmgmt_content` (Phase 5 ingestion) | SELECT, INSERT, UPDATE — **no DELETE** | content **retires** via `withdrawn_at`, it does not vanish |
| `patchmgmt` (owner/migrations) | DDL | unchanged |

`patchmgmt_content` is a new non-owner, non-superuser `LOGIN` role with no `BYPASSRLS`,
created idempotently (`DO $$ … IF NOT EXISTS … $$`) because roles are cluster-global and
outlive the ephemeral per-run test database.

**The exemption is asserted by test, not documented and hoped for.**
`tests/PatchManagement.IntegrationTests/RlsConventionTests.cs` asserts three things:
every *other* table has `tenant_id` + ENABLE + FORCE + a `tenant_isolation` policy; each
of the five global tables has no `tenant_id`, no RLS, and exactly the grants above; and
the set of tables lacking `tenant_id` equals **exactly** `{tenants,
__EFMigrationsHistory} ∪ {the five}`. A sixth global table therefore cannot appear
silently — the test fails until someone edits the list, which makes it a reviewable
frozen-contract change under NEVER #6.

## Consequences

- **One copy of the corpus regardless of tenant count.** Ingest cost is O(sources), not
  O(sources × tenants).
- **Phase 5's sync is tenant-neutral** and needs no tenant GUC. This *partially* defuses
  review M6 — for content ingestion specifically. M6 remains open for Phase 11
  schedules and Phase 8 wave execution, which are genuinely tenant-scoped.
- **`findings` → content FKs are plain single-column** (`advisory_id → advisories(id)`,
  `patch_id → patches(id)`), whereas `findings → assets` is the composite,
  tenant-consistent `(tenant_id, asset_id) → assets(tenant_id, id)`. The asymmetry is
  intentional and follows directly from this decision.
- **A tenant cannot hold private advisories.** If that is ever needed (a customer's own
  internal advisories), it is an **additive tenant-scoped overlay table** — never a
  change to these five, and never a `tenant_id` column bolted onto them.
- **SaaS posture is unchanged or improved.** "Multi-tenant SaaS is a configuration
  change" (CLAUDE.md §3) still holds: shared reference data is the normal SaaS shape.
- **The read barrier for content is role-based, not row-based.** Anyone connecting as
  `patchmgmt_content` can write all content. That role belongs only to the ingestion
  worker; it is not the request-path role.

### Related, and deliberately recorded as unsettled

**`audit_log.tenant_id → tenants(id)` is correct until M4.** The same slice adds that FK
(phantom-tenant writes are the larger risk today — review H3 failure 2 combined with
H1). Its one cost is that an action attempted against a nonexistent tenant cannot be
audited. Review **M4** requires system-scope audit entries — Phase 2's KEK rotation is
explicitly cross-tenant and must be auditable — which will make `audit_log.tenant_id`
**nullable**. A nullable FK stays compatible, so no change is needed now. **Phase 2 must
not treat the non-nullable column as settled.**

## Rejected

- **Tenant-scope the content tables (as originally specified).** N copies of a public
  corpus; forces a per-tenant sync loop through a fail-closed policy with no tenant
  context off the HTTP path (M6). Cost with no isolation benefit — the data is public.
- **Global tables still writable by `patchmgmt_app`.** Simplest wiring, but any
  request-path bug or injection rewrites the shared catalogue for every tenant. No
  blast-radius containment on the input to every assessment decision.
- **Owner-role-only writes (no new role).** Phase 5's sync would then run as the
  migration owner — a superuser-equivalent that bypasses RLS everywhere — which is
  exactly the posture ADR 0006 and the `patchmgmt_app` split exist to avoid.
- **Silently exempt the tables and leave CLAUDE.md §4.1 as written.** Would leave the
  constitution contradicting the schema, which is the *original* C1 defect repeated one
  layer down.
