# 14. Cross-tenant background work is a sweep of per-tenant scopes, not an elevated context

- **Status:** Accepted — **amended 2026-07-25 (re-review C-A, H-A)**, see the amendment below
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

**No elevation is involved at the database layer, and that is the point.** There is no new database
role, no new connection string, no `BYPASSRLS`, no superuser, and no schema change:

- `tenants` carries no `tenant_id` and has no RLS policy, and `patchmgmt_app` already holds
  `GRANT SELECT` on it. Enumerating tenants therefore needs no privilege and exposes no
  tenant-owned data.
- Each scope's tenant is a **concrete id**. There is no "all tenants" value — a null tenant
  still means deny-all, unchanged.
- Every query still runs as the restricted role under `FORCE ROW LEVEL SECURITY`.

So the capability to read two tenants in one query is never created. The worst a misuse
achieves is what a loop of ordinary per-tenant requests could already do.

> **Correction 2026-07-26 (re-review H-D) — the claim above is true of the database and was
> overstated about the application.** Two application-layer capabilities exist that no ordinary
> tenant-scoped request has, and the original wording read as though none did:
>
> - **`ListTenantsAsync` enumerates the registry.** A tenant-scoped caller cannot learn that other
>   tenants exist, let alone their ids. That the read needs no *database* privilege is exactly why
>   it needs an *application* one — the DB will not stop it.
> - **`Create(tenantId)` writes no audit row.** The "misuse is attributable" mitigation below is
>   true only of `SweepAsync` callers that audit inside the sweep, as `KekRotationService` does.
>   A direct `Create` leaves no trace at all.
>
> Neither is a cross-tenant *read* capability — RLS still fences every query — so the isolation
> argument stands. What does not stand is treating "no elevation" as unqualified.
>
> The residual below was recorded as unenforceable in DI, which is true, and then left there.
> `TenantScopeConventionTests` now enforces it the way ADR 0012 decision B enforces the unscrubbed
> scope channel: a source scan with an explicit allowlist — the declaration, the implementation, the
> DI registration, and `KekRotationService` — so a new cross-tenant caller is a deliberate edit
> someone defends rather than an accident. It was mutation-checked: a probe resolving the factory
> under `src/Host/Api` fails the test. Phases 8 and 11 are expected to join that list and should
> audit per tenant as rotation does.
>
> This is a fence, not authorization. **Phase 14** supplies the real gate. **Auditing `Create`
> itself is deferred to Phase 13**, the audit-module owner, and is gated on the same Phase-1 **M4**
> change — `EfAuditLog` saves the caller's shared context, so a write-per-scope would flush the
> caller's state mid-operation. Nothing in the shipped host calls it today: `Program.cs` exposes
> only `/health` and `/diag/assets`, and there is deliberately no rotation trigger.

**The tenant is immutable for the life of the scope.** The GUC is written when a connection
opens (`set_config(..., false)`), so reassigning the tenant on a live scope would silently
not apply to a connection already open. `ITenantScope` exposes no setter; one scope, one
tenant.

**Each tenant is isolated.** A failure is recorded against that tenant and the sweep
continues. Cancellation stops cleanly between tenants and returns a partial result rather
than throwing — `TenantsAttempted` versus `TenantsTotal` makes that visible.

> **Amendment 2026-07-26 (re-review H-C) — a cancelled tenant is reported, never un-counted.**
> Cancellation *between* tenants is clean, as written. Cancellation *inside* one was not: the
> handler decremented `TenantsAttempted` and broke, on the reasoning that the tenant "did not
> complete and was not a failure". But the factory cannot know that — the delegate may have saved
> and then been cancelled during a follow-up write, which is precisely the H-B window below. The
> decrement erased such a tenant from **both** `TenantsAttempted` and `Failures`, so a tenant whose
> rows had actually changed vanished from the result entirely. That is review C1's "did nothing,
> reported success" inverted: *did something, reported nothing*.
>
> The decrement is gone. An interrupted tenant stays counted as attempted and is recorded by name
> with the honest verdict — cancelled after its scope started, committed state unknown — so
> `Complete` is false and the tenant is nameable rather than merely missing (CLAUDE.md §4.6). This
> lives in shared infrastructure that Phases 8 and 11 are told to consume, which is why it is fixed
> rather than deferred: a counter that lies would propagate to every future sweep.

**Only one rotation runs at a time in a process (amendment 2026-07-26, cold review H2).**
`KekRotationService` is a singleton, so two callers share one instance. Without a guard they
interleave destructively: A mints `k1`, B mints `k2`, and A's still-running sweep converges the whole
estate onto `k1` — by then superseded. After a breach that silently restores the compromised key, and
both callers are told it worked. A `SemaphoreSlim(1,1)` now spans **the mint and the sweep together**;
guarding only the sweep would still let both mints land first, which is the same defect with extra
steps. Callers queue rather than being refused, because a `CompleteRotationAsync` waiting behind a
`RotateAsync` is exactly the finish-the-partial-run case, and two serialised `RotateAsync` calls each
converge truthfully — the second simply supersedes the first.

This also protects `ConvergeAsync`'s captured counters, which were only ever safe because one sweep
runs at a time. **That assumption is now load-bearing and is flagged in the code**: parallelising the
sweep for the 10,000-endpoint target corrupts the accounting unless it is converted first (cold
review M5).

**In-process only, and the limit is real.** A second *process* rotating concurrently is not excluded
by this; that remains open and is Phase 15's
([ADR 0016](0016-single-process-vault.md)). What this closes is the case ADR 0016 originally — and
wrongly — filed as multi-process-only.

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

## Amendment 2026-07-25 — two defects in the rotation this ADR introduced

**C-A: the convergence target must be read authoritatively.** `CompleteRotationAsync` took its target
from the cached current key id, refreshed only on a lookup miss. A process that did not perform the
rotation would therefore converge `WHERE key_id != <remembered>` — which matches every DEK another
process already moved forward — and re-wrap the estate **backwards** onto the superseded version,
reporting `Complete = true`. After a breach that silently restores the compromised key.

`IKeyProvider` gains `RefreshCurrentKeyIdAsync`, which re-reads the store under the same exclusive
lock the write path uses. `CompleteRotationAsync` uses it, and so does
`DataKeyService.GetOrCreateActiveAsync` — same root cause, since a non-rotating process would
otherwise seal *new* DEKs under a superseded version until restart.

**Bounded, not eliminated.** The target is authoritative at read time, but the sweep spans many
transactions afterwards, so a rotation by another process mid-sweep still leaves this one converging
onto a now-stale target. That is recoverable by re-running. The window shrinks from "the process
lifetime" to "one sweep"; it is not zero.

**H-A: `Complete` must reflect tenant failures.** `ConvergeAsync` built its result from the per-DEK
failure list and never read `sweep.Failures`. Anything throwing outside the inner try — the DEK
query, the save, the audit append — was recorded as a tenant failure, discarded, and the rotation
reported `Complete = true` with tenants **not rotated at all**. That is the failure this ADR's own C1
fix existed to remove, reappearing one layer up. `KekRotationResult` now carries `TenantFailures`, and
`Complete` requires both failure lists empty.

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
- **The audit append is uncancellable, deliberately (re-review H-B).** It is a *second*
  transaction — `EfAuditLog` calls `SaveChangesAsync` itself — so it compensates for a re-wrap that
  is already durable. Threading the sweep's token through it meant a cancel landing between the two
  writes committed the key change and dropped its only record: probing the vault would leave no
  trail exactly when someone was probing it. `ConvergeAsync` now checks cancellation immediately
  *before* the save, where stopping is still free, and passes `CancellationToken.None` to the
  append — the one place in the module that departs from "a token on every I/O", for a bounded
  single-row insert. **Residual, stated not closed:** a crash rather than a cancel between the two
  writes still loses the row. The real fix is one transaction, which needs `EfAuditLog` to stop
  saving the caller's context — Phase-1 review **M4**, owned by **Phase 13**.
- The per-DEK loop checks cancellation each iteration, so a tenant with many DEKs is interruptible
  without waiting on whatever I/O happened to be awaited next (CLAUDE.md NEVER #5). Throwing there
  abandons the change tracker before any save, so nothing partial commits.
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
