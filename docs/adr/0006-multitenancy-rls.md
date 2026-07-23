# 6. Multi-tenancy with PostgreSQL RLS from day one

- **Status:** Accepted
- **Date:** 2026-07-24

## Context
The product ships on-prem now but must become multi-tenant SaaS via configuration,
not a rewrite. Retrofitting tenant isolation later is error-prone and dangerous for
a security product holding fleet-wide credentials.

## Decision
**Every table carries `tenant_id`** and has a PostgreSQL **row-level security**
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
