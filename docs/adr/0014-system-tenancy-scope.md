# 14. Cross-tenant background work is a sweep of per-tenant scopes, not an elevated context

- **Status:** Accepted
- **Date:** 2026-07-25
- **Amends:** nothing — this fills the gap Phase-1 review **M6** left open
- **Context:** Phase 2 review **C1**; Phase-1 review **M6**

## Context

The only writer of the tenant context was HTTP middleware. Off the HTTP path nothing sets
it, the RLS policy fails closed, and a job sees zero rows and *succeeds*. M6 predicted
this and asked for a sanctioned pattern "or three parallel phases will invent three".

Phase 2 shipped straight into it. `IKekRotationService` was registered against the
request-path `AppDbContext` — the restricted `patchmgmt_app` connection with the RLS
interceptor — while its own interface doc claimed it "runs under a maintenance DB context
that is not restricted by per-tenant RLS". **No such context existed in DI.** Invoked off
the HTTP path it minted a new KEK version, re-wrapped nothing, and returned success, so
"we rotated the KEK" after a breach would have been false while every DEK stayed under the
compromised key. The rotation test passed only because the harness hand-built the service
over an owner-role context that no production wiring produces.

## Decision

**Cross-tenant work is a sweep of ordinary single-tenant scopes.** `ITenantScopeFactory`
(in Contracts, so every module can consume it without depending on Persistence) opens a DI
scope with the tenant pre-set; the existing `RlsConnectionInterceptor` then applies it to
every connection that scope opens. A job gets exactly what a request for that tenant gets.

```
ITenantScope Create(Guid tenantId)                       // targeted job
Task<IReadOnlyList<Guid>> ListTenantsAsync(ct)           // registry only
Task<TenantSweepResult> SweepAsync(operation, work, ct)  // one scope per tenant
```

**No elevation is involved, and that is the point.** There is no new database role, no new
connection string, no `BYPASSRLS`, no superuser, and no schema change:

- `tenants` carries no `tenant_id` and has no RLS policy, and `patchmgmt_app` already holds
  `GRANT SELECT` on it. Enumerating tenants therefore needs no privilege and exposes no
  tenant-owned data.
- Each scope's tenant is a **concrete id**. There is no "all tenants" value — a null tenant
  still means deny-all, unchanged.
- Every query still runs as the restricted role under `FORCE ROW LEVEL SECURITY`.

So the capability to read two tenants in one query is never created. The worst a misuse
achieves is what a loop of ordinary per-tenant requests could already do.

**The tenant is immutable for the life of the scope.** The GUC is written when a connection
opens (`set_config(..., false)`), so reassigning the tenant on a live scope would silently
not apply to a connection already open. `ITenantScope` exposes no setter; one scope, one
tenant.

**Each tenant is isolated.** A failure is recorded against that tenant and the sweep
continues. Cancellation stops cleanly between tenants and returns a partial result rather
than throwing — `TenantsAttempted` versus `TenantsTotal` makes that visible.

**Rotation is now resumable.** `RotateAsync` mints a version and converges;
`CompleteRotationAsync` converges onto the **existing current** version without minting.
A retry after a partial run finishes the remainder instead of minting a key per attempt.
Convergence selects only DEKs not already on the target, and each DEK re-wraps in its own
try/catch — so one corrupt or relocated row fails alone rather than aborting the estate,
which is the robustness gap ADR 0013 flagged.

**The per-tenant scope is the batching unit.** Each tenant saves and audits on its own, so
no single transaction spans the estate. The rotation working set is O(tenants) — roughly one
active DEK each — not O(endpoints). Tenant counts are stated nowhere in the docs and on-prem
is the primary deployment, so intra-tenant paging would be speculative; the sweep is already
incremental if that changes.

**All tenants are swept regardless of `status`.** A suspended tenant's credentials would
otherwise stay under a compromised KEK, defeating the purpose of a post-breach rotation.
`tenants.status` has no CHECK constraint (only `'active'` is ever observed), so filtering on
it would be guesswork as well as unsafe.

## Consequences

- M6 is answered for the tenant-scoped flavour. **Phases 8 (wave execution) and 11
  (schedules) should consume `ITenantScopeFactory` rather than invent their own.**
- **Phase 5 is explicitly out of scope.** Content ingestion is tenant-*neutral*: it writes
  global tables under its own `patchmgmt_content` role and needs no tenant at all (ADR 0010).
  Do not route it through this.
- Audit stays per-tenant, written inside each tenant's own scope, which satisfies the
  `audit_log` `WITH CHECK` naturally. M4 remains open — a genuine "the system did X" record
  still needs `AuditEntry.TenantId` to become nullable, and this design does not treat the
  non-nullable column as permanent.
- `KekRotationService` is now a singleton: it creates its own scopes, so a background job
  resolves it from the root without ceremony.
- **Residual risk, stated rather than hidden:** DI cannot prevent request-path code
  resolving the factory and looping tenants. Mitigations are that every sweep writes
  per-tenant audit rows, so misuse is attributable, and that Phase 14 will gate the trigger.
  There is deliberately no trigger today — rotation is invocable and proven by test, and real
  scheduling arrives with Hangfire in Phase 11.

## Rejected

- **A `BYPASSRLS` or superuser maintenance role.** It is the only thing that defeats
  `FORCE ROW LEVEL SECURITY`, so it would make the privileged path a genuine cross-tenant
  bypass — a worse posture than the bug being fixed. ADR 0010 rejected the same move for
  Phase 5: "a superuser-equivalent that bypasses RLS everywhere — exactly the posture ADR
  0006 and the `patchmgmt_app` split exist to avoid". `RlsConventionTests` also asserts the
  application roles hold no `BYPASSRLS`.
- **A second owner-role `AppDbContext` for maintenance.** Same objection, plus it would need
  an elevated credential wired into the running host, which none exists today.
- **An "all tenants" sentinel on the tenant context.** One mistake — a request that fails to
  set a tenant, or sets the sentinel — silently becomes a cross-tenant read. Fail-closed must
  stay the only meaning of "no tenant".
- **Filtering the sweep to active tenants.** See above: it silently leaves credentials under
  a compromised key.
