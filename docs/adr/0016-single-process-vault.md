# 16. The vault is correct for a single process; production multi-process arrives via KMS

- **Status:** Accepted — **amended 2026-07-26 (cold review)**, see "Two premises were wrong" below
- **Date:** 2026-07-26
- **Amends:** the Phase 2 exit criteria in `docs/ROADMAP.md` and `docs/phases/phase-2.md`
  (provider swappability and the KMS backends move to Phase 15)
- **Context:** Phase 2 re-review — the open findings H-2, H-3, M-1, M-2, and C-A's residual window

> **Amendment 2026-07-26 — two of this ADR's deferrals rested on false premises.** A zero-history
> cold review confirmed the core (cross-process custody, no version loss, absence-fatal
> initialization, the H-1 deep copy, envelope relocation failing, no downgrade, no cross-tenant
> bypass — verified on Windows, glibc and musl) and then **disproved two things this document
> asserted**. Both are corrected below and both were fixed rather than re-deferred. A deferral
> justified by a false premise is worse than no deferral: it reads as settled, so nobody checks it
> again.

## Context

The Phase 2 re-review left eight findings undispositioned. Reading them together shows they are not
eight problems but two: a handful of genuine defects that bite in any deployment, and a cluster that
only bites when **two processes share one KEK file**.

That second cluster kept the branch unmergeable for the wrong reason. Every fix for it — a
lease protocol, a read-only-mount read path, a cross-process test harness, durability assertions
that a Windows dev box cannot run — is real engineering aimed at a deployment shape **the product
does not currently have and, at production scale, should never have**.

Nothing in the repository claims multi-instance today. `CLAUDE.md` §3 ships an on-premises Docker
Compose stack. No ADR, phase document, or `THREAT-MODEL.md` section describes a second replica, a
shared key volume, or an HA topology. The one commitment pointing that way is §3's "architected so
multi-tenant SaaS is a configuration change, not a rewrite" — and SaaS is precisely where a customer
has a KMS.

`SoftwareKeyProvider` exists for the on-prem and air-gapped case ADR 0002 describes: zero external
dependency, one host, one key file. Hardening a shared file into a distributed key store would
rebuild, badly, what Azure Key Vault, AWS KMS and HashiCorp Vault already are — and ADR 0015 already
rejected a Redis lock for contradicting the same zero-dependency premise that makes the software
provider worth having.

## Decision

**The software key provider is supported for a single process. Production multi-process deployment
is served by the KMS backends of `IKeyProvider` (ADR 0002), not by hardening shared-file custody.**

Concretely:

1. **Single-process is the supported shape for `VAULT_KEY_PROVIDER=software`.** One host, one
   process, one key file. This is the on-prem and air-gapped case, and it is where the provider's
   value lies.
2. **The existing cross-process machinery stays.** ADR 0015's sidecar lock, reload-under-lock, and
   durable-before-published write are *not* reverted. They cost nothing, they make the single-process
   case correct across restarts, and they turn the two-process case from silent unrecoverable data
   loss into something bounded. They are a safety net, **not a supported topology** — that
   distinction is the whole of this ADR.
3. **Multi-instance and SaaS require a KMS provider.** Under Azure Key Vault, AWS KMS or HashiCorp
   Vault the KEK never resides on the host: wrap and unwrap happen in the KMS, custody is already
   shared and already concurrent, and every finding below is answered by the backend rather than by
   us. **Phase 15 owns building them**, and no multi-instance deployment is supported before it
   ships.
4. **The five multi-process findings are deferred to Phase 15 with that reasoning attached**, so a
   future session reads them as scoped, not as oversights.

## Two premises were wrong (cold review, 2026-07-26)

### 1. "Concurrent rotation damage is multi-process only" — false

This ADR framed the whole concurrent-rotation hazard as something a KMS would answer, on the
assumption that concurrency required a second process. **`KekRotationService` is a singleton**, so one
process is enough: two callers share the instance, A mints `k1`, B mints `k2`, and A's still-running
sweep converges the estate onto `k1` — by then superseded. After a breach that silently restores the
compromised key, and both callers are told it worked. It bit the **single-process topology this ADR
had just declared supported**.

**Fixed, not deferred** (cold review H2): a rotation gate spanning the mint *and* the sweep, proven by
a deterministic forced interleave rather than a timing race. See
[ADR 0014](0014-system-tenancy-scope.md).

**What genuinely remains multi-process** is narrower and is stated precisely: a second *process*
rotating concurrently is not excluded by an in-process semaphore. That stays with Phase 15, together
with C-A's residual window, which is the same shape.

### 2. "`DllImport` on musl throws, so the fsync fix is blocked" — false

The H-3 row below asserted that `DllImport("libc")` can fail to resolve on musl, which was the stated
reason for deferring a three-line try/catch. **The cold review ran it on musl and it resolves fine.**

Worse, the real defect was never the one described: `Fsync`'s return value was **discarded**, so
`EIO` — the exact failure the call exists to detect — vanished silently. **Fixed, not deferred** (cold
review M6): the body cannot throw past the committed rename, and a failing `open` or `fsync` is logged
with its errno. The ADR 0015 correction that asserted the musl premise is retracted there.

**Both rows are struck from the deferral table below.** The remaining deferrals are re-derived on
grounds that survive contact with a reviewer who ran the code.

## What is deferred, and why each is genuinely multi-process

| # | Finding | Why it only bites under multi-process |
|---|---|---|
| **H-2** | Every `IKekSource` entry point takes the sidecar lock, opened `OpenOrCreate` + `ReadWrite`, so a **read-only key mount cannot even boot** — the read path needs *create* access, not just write | A read-only mounted secret is a managed-orchestrator pattern. A single host owns its key file and can write beside it. Under KMS there is no key file at all |
| ~~**H-3**~~ | ~~`FsyncDirectory` can throw on musl~~ | **STRUCK 2026-07-26 — premise false, and fixed.** See "Two premises were wrong" above |
| **M-1** | The **cross-process** file-lock guarantee is untested. `Concurrent_rotations_do_not_erase_each_others_key_versions` serialises — the uncontended lock and flush path completes synchronously, so `Task.WhenAll` awaits two finished tasks, and it would pass with the sidecar lock deleted | **Re-derived.** The *in-process* half of this gap is now closed: `ConcurrentRotationTests` forces a real interleave of two rotations and proves the sweep guard. What remains untested is mutual exclusion **across processes**, which needs a second-process harness this repo does not have |
| **M-2** | Nothing tests durability — `WriteThrough`, `Flush(flushToDisk: true)` and the directory fsync are unasserted, and fsync is a deliberate no-op on the Windows dev box. No lock-contention or timeout test either | Needs a Linux CI runner and crash injection. The single-process consequence is bounded by restore-from-backup; the multi-process one is divergence between live processes |
| **C-A residual** | The convergence target is authoritative at read time, but the sweep spans many transactions, so a rotation by **another process** mid-sweep leaves this one converging onto a stale target. Recoverable by re-running | Genuinely cross-process, and now the *only* remaining form of the concurrent-rotation hazard: the in-process case is fixed above. Phase 15 should treat this and M-1 as one problem — cross-process rotation exclusion — rather than two |

**Also owned by Phase 15**, being the same subject:

- **H7** — the default KEK path is container-ephemeral (`AppContext.BaseDirectory/vault/kek.json`)
  and there is no escrow or replication. Single-file custody is a single point of total loss.
- **H8** — a misconfigured KMS provider throws on first use, not at startup: the app boots green,
  passes `/health`, and fails on the first credential operation.
- **The KEK retirement floor** — refusing superseded versions once convergence is provably complete.
  This is the safe form of what `phase-2.md` wrongly claimed rotation already did (H-D2), and it is
  what would actually close **M-6**; see [ADR 0013](0013-envelope-binding.md).

## The recurring hazard: this subsystem reports success while untrue

Recorded here because it is the most transferable thing four reviews have produced, and because each
instance looked like an isolated bug until they were listed together:

| # | Instance | Shape |
|---|---|---|
| 1 | Review **C1** | Rotation ran under RLS off the HTTP path, saw zero rows, re-wrapped nothing, returned `KekRotationResult(newKeyId, 0, 0)` — a success |
| 2 | Re-review **H-A** | `ConvergeAsync` built its result from the per-DEK list and never read `sweep.Failures`, so tenants that were never rotated did not count against `Complete` |
| 3 | Re-review **CR-1 / C-A** | A rotation with the key file absent discarded every KEK version and reported success; `CompleteRotationAsync` re-wrapped the estate *backwards* onto a superseded key and reported `Complete` |
| 4 | Cold review **H1** | Skipped DEKs — an adversary's chosen rows — did not count against `Complete` |

Two patterns worth internalising:

- **Fixing the number is not fixing the verdict.** The H-A fix split the counters so the *numbers*
  became honest, and the dishonesty simply relocated into `Complete`, where it survived another
  review. Instance 4 exists because instance 2's fix stopped one level too early.
- **Every one of these is exploitable in the same direction.** A false `Complete` means the operator
  does not re-run, which is precisely what an adversary wants after a breach. The failure mode is not
  "a confusing report"; it is "the compromised key stays in service with the operator's confidence".

**So: treat every success signal in this subsystem as guilty until proven.** When you change one, ask
what a caller *does* on `true` — here they stop, and do not re-run — and who benefits if it is wrong.
Prove it red-first against the specific condition, not against an adjacent one that happens to fail.
`KekRotationResult.Complete` carries a pointer to this section for whoever edits it next.

## Consequences

- **Phase 2's exit criteria are amended.** Provider swappability and the three KMS backends move to
  Phase 15. Recorded here and in the ROADMAP so it reads as a scope move, not a lowered bar — the
  same shape as the C1 amendment to Phase 1.
- **A deployment constraint now exists and must be documented for customers, not just for us:**
  running more than one instance against a shared key file is unsupported. Until Phase 15, the
  supported topologies are single-instance on-prem (software provider) and nothing else.
- **`docker-compose.yml` must not gain a second app replica** before Phase 15, and H7's missing key
  volume is now owned rather than floating.
- The safety net in ADR 0015 means the unsupported shape degrades rather than corrupts: concurrent
  rotations are additive, and a losing writer's version still unwraps.
- **This does not weaken any at-rest or cross-tenant guarantee.** Envelope binding (ADR 0013), RLS,
  and the never-log invariants are unaffected — they are per-record and per-process properties.

## Rejected

- **Harden shared-file custody now.** It rebuilds a distributed key store out of a file and a
  `flock`, for a topology no customer has yet, while three KMS backends that solve it properly sit
  as stubs. ADR 0015 already rejected a Redis lock on the adjacent ground that it contradicts the
  zero-external-dependency premise the software provider exists to serve.
- **Rip out the cross-process lock as unsupported.** It is already written, already tested as far as
  one process can test it, and turns unrecoverable loss into bounded degradation. Removing a working
  safety net to make a support boundary tidier is a bad trade.
- **Say nothing and merge.** The findings would read as oversights to the next reviewer, and
  `DIFFERENTIATORS.md` forbids deferring without a named owner. That rule is why Phase 15 exists
  rather than another line in the "Phase 2 hardening" bucket the ROADMAP already calls a naming dodge.
- **Declare multi-process supported because the lock exists.** ADR 0015 states plainly that the
  cross-process guarantee is *argued, not test-proven* — no second-process harness, and the
  directory fsync is unexercised on the dev platform. Claiming support on that basis would be the
  kind of unearned assurance this project keeps finding and removing.
