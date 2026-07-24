# 6. Multi-tenancy with PostgreSQL RLS from day one

- **Status:** Accepted — **amended by [ADR 0010](0010-global-content-catalogue.md) (2026-07-24)**
- **Date:** 2026-07-24

> **Amendment.** "Every table carries `tenant_id`" below now reads "every **tenant-scoped**
> table". ADR 0010 carves out one named exemption — the global content catalogue
> (`content_sources`, `advisories`, `advisory_affects`, `patches`, `patch_supersedence`) — which
> holds public vendor content identical for every tenant, carries no `tenant_id`, has no RLS, and
> is isolated by **role** instead. Nothing else in this ADR changes: the isolation model, the
> fail-closed policy, the non-owner app role, and the "SaaS is configuration" goal all stand.

## Context
The product ships on-prem now but must become multi-tenant SaaS via configuration,
not a rewrite. Retrofitting tenant isolation later is error-prone and dangerous for
a security product holding fleet-wide credentials.

## Decision
**Every tenant-scoped table carries `tenant_id`** (see the amendment above) and has a
PostgreSQL **row-level security**
policy keyed on `current_setting('app.tenant_id')`. The app sets the tenant context
per request; the database enforces isolation with `FORCE ROW LEVEL SECURITY`, and
the app connects as a **non-owner role** so RLS actually applies. Single-tenant
on-prem is simply "one tenant".

## Consequences
- A code bug cannot leak across tenants — the database is the backstop.
- Slight overhead setting tenant context per connection; migrations run as owner.

## Rejected
- **App-layer filtering only** — one missing `WHERE` leaks data.
- **Schema/DB-per-tenant now** — heavier ops; can layer on later if needed.
