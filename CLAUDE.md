# CLAUDE.md — Project Constitution

> Read this first, every session. It governs how this product is built. When a
> request conflicts with this file, stop and ask.

## 1. Purpose

An **enterprise, agentless patch-management platform** — discover endpoints,
assess them against authoritative vulnerability/patch content, deploy patches in
controlled waves, verify the result, and prove compliance. Sold to customers as a
real product (inspired by Ivanti Security Controls; **no proprietary code or
assets are copied** — everything is built from scratch).

## 2. The agentless constraint (non-negotiable)

**Nothing is ever installed on a managed endpoint.** All work happens over
standard remote-management protocols:

- **Windows** — WinRM, WMI, PowerShell Remoting, SMB.
- **Linux** — SSH, `sudo`, SFTP.

If a feature seems to need an agent, it is out of scope or must be redesigned to
run remotely. This constraint shapes every layer — connection concurrency (not
the database) is the scaling wall at our 10,000-endpoint target.

## 3. Stack

- **Backend**: .NET 9 / ASP.NET Core, EF Core, PostgreSQL 16, Redis, Hangfire
  (background jobs), SignalR (realtime).
- **Frontend**: React + TypeScript + MUI.
- **Architecture**: Clean Architecture, CQRS, dependency injection, SOLID,
  **modular monorepo**.
- **Deployment**: on-premises Docker Compose stack, **architected so multi-tenant
  SaaS is a configuration change, not a rewrite**.

## 4. Architecture rules

1. **Multi-tenant from day one.** Every **tenant-scoped** table carries `tenant_id`.
   PostgreSQL **row-level security (RLS)** is enforced at the database layer — the app
   sets the tenant context per request; the DB refuses cross-tenant reads/writes.
   **One named exemption — the global content catalogue.** `content_sources`,
   `advisories`, `advisory_affects`, `patches`, and `patch_supersedence` hold public
   vendor content that is identical for every tenant. They carry **no `tenant_id`** and
   have **no RLS**; they are **read-only** to `patchmgmt_app` and written only by
   `patchmgmt_content`. The exemption list is **asserted by test**
   (`RlsConventionTests`), so a sixth global table cannot appear silently — adding one
   means editing that list and is a frozen-contract change under NEVER #6.
   See `docs/adr/0010-global-content-catalogue.md`.
2. **Clean Architecture layering.** Domain → Application → Infrastructure → API.
   Dependencies point inward. Domain has no framework/IO dependencies.
3. **CQRS with an in-house mediator.** Commands and queries are separate. We use
   a small first-party `IRequest`/`IRequestHandler` dispatcher — **not** MediatR
   or AutoMapper (both became commercially licensed in 2025; see
   `docs/adr/0005-cqrs-mediator.md`). No black-box mapping libraries.
4. **Modular monorepo.** Features are vertical modules under `src/Modules/*`
   (Vault, Connectors, Discovery, Content, Assessment, Risk, Deployment, …), each
   self-contained with its own domain/application/infrastructure.
5. **Contracts are frozen artifacts.** The schema, RLS policies, OpenAPI, JSON
   schemas, and the endpoint state machine (Phase 1) are contracts. Changing a
   frozen contract requires an explicit ask (see NEVER list).
6. **Everything explainable.** Risk scores, assessment decisions, and blast-radius
   estimates must be traceable to their inputs. No unexplained numbers.

## 5. Coding conventions

- **C#**: nullable reference types on; `async`/`await` end-to-end; `CancellationToken`
  on every I/O and every endpoint operation (see time-bound rule). File-scoped
  namespaces. One public type per file. Records for DTOs/value objects.
- **TypeScript**: `strict` on; no `any` without a written reason; function
  components + hooks; MUI theming, no inline style sprawl.
- **Naming**: intention-revealing. Match the surrounding code's idiom.
- **Errors**: never swallow. Endpoint operations return typed results that model
  failure (see the honest state model), not exceptions-as-flow.
- **Tests colocated** per module under `tests/`.

## 6. Testing requirements

- **.NET**: xUnit. Unit tests for domain/application; integration tests for
  infrastructure that run against the **lab fleet** and the root Postgres/Redis.
- **Web**: Vitest + React Testing Library.
- **No phase is "done"** until its exit criteria in `docs/ROADMAP.md` are met and
  its tests pass. Never mark a ROADMAP phase complete with failing/partial tests.
- **Verification tests must not trust exit codes** — they assert observed state
  (see NEVER list item 3 and `docs/HARD-PROBLEMS.md`).

## 7. The NEVER list (hard rules)

1. **Never log credentials** — not passwords, keys, tokens, decrypted secrets, nor
   the plaintext of any vault item, at any log level.
2. **Never return credentials from any API** — no endpoint, DTO, event, or error
   message ever emits a stored secret back to a caller.
3. **Never trust an installer exit code as proof of patching** — exit 0 is a hint,
   not evidence. Patch state is confirmed only by re-observing the endpoint.
4. **Never target a non-lab machine** during development. The only legitimate
   endpoints in dev are the local lab containers on `localhost` (enforced by the
   guardrail in `.claude/`). Roaming/production targets are never touched from a
   dev session.
5. **Every endpoint operation must be idempotent and time-bounded** — safe to
   retry, and carrying an explicit timeout/`CancellationToken`. No unbounded
   remote calls.
6. **Never change a frozen contract without asking** — schema, RLS, OpenAPI, JSON
   schemas, or the state machine. Propose the change and wait for approval.

## 8. Pointers

- Master plan & phase status → `docs/ROADMAP.md`
- How to run sessions / parallelism / merges → `docs/WORKFLOW.md`
- Known hard problems & chosen approaches → `docs/HARD-PROBLEMS.md`
- Credential-store threat model → `docs/THREAT-MODEL.md`
- Designed-in differentiators → `docs/DIFFERENTIATORS.md`
- Architecture decisions → `docs/adr/`
