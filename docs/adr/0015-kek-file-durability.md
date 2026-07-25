# 15. The KEK key file is written durably, atomically, and under a cross-process lock

- **Status:** Accepted — **amended 2026-07-25 (re-review CR-1)**, see "Absence is an error" below
- **Date:** 2026-07-25
- **Amends:** the `IKekSource` shape (removes `SaveAsync`) and makes `KekKeyset` immutable
- **Context:** Phase 2 review **C2**, **C3**, **C4** (and, inseparably, **H2** and **H6**)

## Context

Three review criticals sat in one broken write path. Losing a KEK version bricks every DEK
wrapped under it, and every credential under those — so each is total, unrecoverable data
loss, not a disclosure risk.

- **C4 — a version could be live before it was durable.** `AddNewCurrent()` mutated the
  cached keyset and moved `CurrentKeyId` *before* `SaveAsync` ran, with no rollback. A
  failed write left new DEKs wrapped under a KEK that existed only in RAM.
- **C3 — nothing was flushed.** Temp-then-rename was the right shape, but with no
  `WriteThrough`, no `Flush(flushToDisk: true)`, and no directory fsync, neither the file's
  contents nor the rename were durable.
- **C2 — the writer wrote a stale snapshot.** The keyset was cached for the process
  lifetime with no reload, and `SaveAsync` wrote that whole cached snapshot over the file.
  Two processes on a shared volume therefore erased each other's versions. Only an
  in-process `SemaphoreSlim` guarded it — which is no guard at all across processes.

Both C2 and C4 were reproduced against the unmodified code before the fix.

## Decision

### One atomic, durable read-modify-write

`IKekSource.SaveAsync` is **removed**. "Load, mutate, save" is precisely the shape that let
a stale snapshot overwrite the file, so it is no longer expressible by a caller. Adding a
version is a single operation the store performs on itself:

```
AddVersionAsync:
  1. take an exclusive lock on a sidecar `<path>.lock`
  2. re-read the keyset FROM DISK          ← never from a cache
  3. keyset = onDisk.WithNewVersion()
  4. temp file → flush to disk → atomic rename → fsync the directory
  5. release the lock and return the keyset
```

**Reload-under-lock is the merge (C2).** The second writer reloads *after* the first has
committed, so it extends that keyset rather than replacing it; the union is automatic and
no version is ever erased. Nothing compares or orders key ids — which matters, because
`NewKeyId()` uses `DateTime.UtcNow` at second resolution truncated to 40 chars and is **not
orderable**. `current` comes from the file's own field, last writer wins, and since every
version survives, a "losing" writer's key still unwraps.

**A sidecar lock, not the key file.** The atomic rename replaces the key file, which would
invalidate a lock held on it mid-write. `FileShare.None` is enforced by the OS per handle —
mandatory on Windows, an advisory `flock` on Unix — so it holds across processes. Acquisition
retries with backoff and fails as a `TimeoutException` naming the lock path rather than
hanging.

**Durability chain (C3).** `FileOptions.WriteThrough` plus an explicit
`Flush(flushToDisk: true)` before close gets the *contents* onto the device; `File.Move` with
overwrite is an atomic rename on a single volume; and an **fsync of the parent directory**
makes the *rename* durable. Without that last step a power loss can silently revert to the
previous key file — losing a version already reported as current, which is C4 arriving by
another route. .NET exposes no managed API for it, so it is a `DllImport` of
`open`/`fsync`/`close`, guarded by `OperatingSystem.IsWindows()` and a documented no-op
there (NTFS journals the rename and there is no directory handle to sync) — the same
OS-conditional idiom `HardenPermissions` already used in this file.

`DllImport` rather than the source-generated `LibraryImport` deliberately: the latter
requires `AllowUnsafeBlocks`, and enabling unsafe code across a module that handles key
material is a poor trade for three calls with no pointer arguments.

**Durable before believed (C4).** `AddVersionAsync` returns only after the rename is
durable. `SoftwareKeyProvider` then swaps its cached reference — a single assignment of an
immutable value. If the write throws, the cache is untouched, so nothing can be wrapped
under a version that is not on disk.

### Absence is an error; initialization is opt-in (amendment, re-review CR-1)

The original decision above — "re-read the keyset FROM DISK, never from a cache" — was right about
staleness and **wrong about absence**. `ReadOrCreateAsync` treated a missing file as first boot, so a
rotation whose key file had vanished durably replaced the entire keyset with one fresh key and
reported success, bricking every DEK. Removing `SaveAsync` is what made this unrecoverable: the old
"load, mutate, save" path rewrote every version from a warm cache, so a vanished file was
self-healing. **The recovery path became the destruction path.**

Creation was reachable from three call sites, not one. The worst was `ReloadAsync`, which fires on a
cache miss *while unwrapping existing ciphertext* — it cannot possibly produce the key being sought,
and it overwrote the real store on its way to failing.

So:

- `IKekSource` splits the intents. `LoadOrInitializeAsync` is cold start only and may create;
  `ReadAsync` never creates and treats absence as an error; `AddVersionAsync` reads through the
  absence-is-fatal path.
- `KeyFileKekSource` takes `allowInitialize` (default **false**), set from `VAULT_SOFTWARE_KEK_INIT`.
  It gates cold start only — `ReadAsync` and `AddVersionAsync` ignore it entirely.
- The refusal message is deliberately actionable: it names the resolved path, says how to initialize,
  and warns that initializing when credentials already exist makes them unrecoverable.

**Why opt-in rather than "create at cold start only".** An absent store is indistinguishable from an
unreachable one — an unmounted volume, a wrong path, a changed working directory — and after first
boot the second is far more likely. Minting a KEK in that moment silently bifurcates the key
hierarchy: pre-existing DEKs become unopenable while new ones are sealed under a key the estate has
never seen. That cost is unbounded and unrecoverable; the cost of requiring one deliberate act at
first boot is a documented step.

### `KekKeyset` becomes immutable

Required, not cosmetic: publishing a new keyset by reference swap is only safe if the value
cannot change under a concurrent reader. `AddNewCurrent()` (mutating) becomes
`WithNewVersion()` returning a new instance, `CurrentKeyId` is get-only, and `Snapshot()`
returns a copy instead of the live dictionary. This also closes **H6** — `Get()` is called
from `Wrap`/`Unwrap` outside the provider's gate, and was racing a `Dictionary` that
rotation mutated in place.

> **Amendment 2026-07-26 (re-review H-1) — immutability now covers the key material, not just the
> map.** As originally written this section was true of the *dictionary* and false of its contents.
> Every accessor — the constructor, `WithNewVersion()`, `Snapshot()`, and `Get()`/`TryGet()` — copied
> only the map and shared the `byte[]` values, so a caller held a live reference to key material the
> provider was concurrently wrapping under, and a parent keyset aliased every version of its child.
> `Snapshot()`'s own doc claimed a holder "cannot observe or affect this keyset", which was not the
> case. Structural immutability over shared mutable arrays is not immutability.
>
> The keyset now **owns** its material: deep-copied in on construction and in `WithNewVersion()`,
> deep-copied out of `Snapshot()`. `Get`/`TryGet` are replaced by `Contains` (a pure predicate that
> hands out nothing) plus `CopyKeyTo(keyId, Span<byte>)`, which writes into a caller-supplied buffer
> — in practice a `PinnedBuffer` — so material travels from the keyset into pinned, self-zeroing
> storage with no intermediate array. `SoftwareKeyProvider.ResolveKeyAsync` returns that
> `PinnedBuffer`, making the zeroing structural (a `using` covers the exception path too) rather
> than something a caller must remember. A wrong-sized destination throws instead of truncating: a
> silently short KEK would produce ciphertext nothing can open.
>
> The consequence worth naming is not tampering but *destruction*. Before this, an ordinary
> `using` around a resolved KEK would have zeroed the live keyset for every subsequent wrap in the
> process. `KekKeysetTests` pins that case specifically, alongside the four aliasing paths, each
> proven red-first against the unmodified code.
>
> `KeyFileKekSource.WriteDurablyAsync` now zeroes the arrays `Snapshot()` hands it once they are
> encoded. The base64 `string`s that replace them remain unzeroable — the recorded KEK
> memory-hygiene limitation, unchanged.

### Stale reads reload once

A `Get` miss now reloads from the source before failing, so a version another process minted
is picked up instead of causing `KeyNotFoundException` until restart — C2's second, quieter
half.

### Also closed, inseparably

**H2** — the temp file is created `0600` via `FileStreamOptions.UnixCreateMode` at creation
time rather than hardened after writing, so there is no window in which the key material is
world-readable, and it is deleted if the write fails. Writing this new writer without that
would have meant knowingly reintroducing the hole in fresh code.

## Consequences

- Concurrent rotations are additive rather than destructive; the losing writer's version
  survives and still unwraps.
- A failed write is now a no-op from the caller's perspective: previous keyset intact on
  disk, unchanged in memory, current key unmoved.
- Rotation serialises across processes. Contention is bounded by `LockTimeout` (30s) and
  surfaces as a typed timeout rather than a hang or a silent overwrite.
- `IKekSource` implementations must now provide atomicity and durability themselves. There
  are two: `KeyFileKekSource` and the test double.

## Limitations, stated rather than implied

- **The cross-process guarantee is argued, not test-proven.** The tests run two independent
  source+provider pairs over one file in one process — but not a true process boundary. There is no
  console project or second-process harness in this repo, and Smart App Control has historically
  blocked spawning freshly built binaries here. The guarantee rests on documented
  `FileShare.None` semantics.

  > **Correction 2026-07-26 (re-review M-1).** This bullet claimed the test "does exercise the real
  > OS lock, since `FileShare.None` is per-handle". It does not. `Concurrent_rotations_do_not_erase_each_others_key_versions`
  > **serialises**: the first provider's whole read-modify-write — uncontended lock acquisition, a
  > small synchronous serialize and flush, release — completes before the second call is even
  > invoked, so `Task.WhenAll` awaits two already-finished tasks. The retry/backoff path is never
  > entered, and **the test would still pass with the sidecar lock deleted entirely**, provided the
  > reload-from-disk in `AddVersionAsync` survives. What it genuinely proves is the additive merge,
  > which is valuable and is what C2 was about — it proves nothing about mutual exclusion. A real
  > concurrency test needs a second process; owned by **Phase 15** ([ADR 0016](0016-single-process-vault.md)).
- **The directory fsync is not exercised on Windows**, where it is a deliberate no-op, and
  the dev/test machine is Windows. The Linux path is reasoned, not run, until CI runs on
  Linux.
- **The fsync is best-effort**: a failure does not fail the rotation, because the contents
  are already durable and the previous keyset is intact. It is a narrowing of the window,
  not an absolute guarantee.

  > **Correction 2026-07-26 (re-review H-3), itself PARTLY RETRACTED the same day (cold review M6).**
  >
  > The correction was right that "best-effort" was aspirational: `FsyncDirectory` discarded
  > `fsync`'s return, so **`EIO` — the exact failure the call exists to detect — was swallowed in
  > silence**, and with no `try`/`catch` any throw escaped `WriteDurablyAsync` *after* `File.Move`
  > had committed, reporting a failed rotation for one that was durable and leaving
  > `SoftwareKeyProvider` on its superseded key.
  >
  > **It was wrong about the cause, and the wrong cause became a reason to defer.** It claimed
  > `DllImport("libc")` can fail to resolve on **musl** and used that to hand a three-line fix to
  > Phase 15. A cold review **ran it on musl: it resolves fine.** The premise was false and the fix
  > was never blocked on anything.
  >
  > **Now fixed here, not deferred.** The whole body is guarded so nothing can escape past the
  > committed rename; a failing `open` or `fsync` logs with its errno through an optional
  > `ILogger`. Best-effort finally means *reported* rather than *invisible*. The lesson is recorded
  > in [ADR 0016](0016-single-process-vault.md): a deferral resting on an unverified premise reads as
  > settled and stops being re-examined.
- **Network filesystems are out of scope.** `flock` over NFS/SMB is unreliable; the lock's
  guarantee is for a local volume. A shared key file on a network mount is not supported.
- Single-file custody remains a single point of total loss (no escrow, no replication) —
  see H7 on the container-ephemeral default path, still open.

## Rejected

- **A Redis-based distributed lock.** There is no Redis client package in the solution, and
  the software provider's stated value in ADR 0002 and `phase-2.md` is "zero external
  dependency — works on-prem and air-gapped". A lock that requires a network service
  contradicts that.
- **Keeping `SaveAsync` and locking at the call site.** It leaves the unsafe pattern
  available to the next caller, and puts the store's atomicity in the hands of whoever
  happens to use it.
- **Locking the key file itself.** The rename replaces it, invalidating the lock mid-write.
- **Enabling `AllowUnsafeBlocks`** to use `LibraryImport` — see above.
