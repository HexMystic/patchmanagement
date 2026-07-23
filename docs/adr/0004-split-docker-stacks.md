# 4. Split Docker stacks: product infra vs target fleet

- **Status:** Accepted
- **Date:** 2026-07-24

## Context
The product needs Postgres + Redis. The dev environment also needs a fleet of Linux
machines to patch. Bundling both in one compose file conflates "the product" with
"the endpoints it manages" and complicates the worktree model.

## Decision
Two independent Compose stacks:
- **Root `docker-compose.yml`** — product infrastructure (Postgres 16, Redis).
- **`/lab/docker-compose.yml`** — the Linux target fleet only.

Only the **main worktree** runs the root infra; other worktrees connect to it. The
app reaches lab targets via host-published `localhost` ports
(`host.docker.internal` from inside containers). `/lab` stays independent.

## Consequences
- Clean conceptual line; worktrees share one infra stack (see `docs/WORKFLOW.md`).
- The guardrail's "lab targets are on localhost" invariant holds, making
  localhost-only SSH enforcement meaningful (ADR 0007).

## Rejected
- **Bundle pg/redis into /lab** (as originally prompted) — conflates concerns and
  fights the worktree model.
