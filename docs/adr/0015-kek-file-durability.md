# 15. The KEK key file is written durably, atomically, and under a cross-process lock

- **Status:** Accepted
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

### `KekKeyset` becomes immutable

Required, not cosmetic: publishing a new keyset by reference swap is only safe if the value
cannot change under a concurrent reader. `AddNewCurrent()` (mutating) becomes
`WithNewVersion()` returning a new instance, `CurrentKeyId` is get-only, and `Snapshot()`
returns a copy instead of the live dictionary. This also closes **H6** — `Get()` is called
from `Wrap`/`Unwrap` outside the provider's gate, and was racing a `Dictionary` that
rotation mutated in place.

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
  source+provider pairs over one file in one process — which does exercise the real OS lock,
  since `FileShare.None` is per-handle — but not a true process boundary. There is no console
  project or second-process harness in this repo, and Smart App Control has historically
  blocked spawning freshly built binaries here. The guarantee rests on documented
  `FileShare.None` semantics plus that test.
- **The directory fsync is not exercised on Windows**, where it is a deliberate no-op, and
  the dev/test machine is Windows. The Linux path is reasoned, not run, until CI runs on
  Linux.
- **The fsync is best-effort**: a failure does not fail the rotation, because the contents
  are already durable and the previous keyset is intact. It is a narrowing of the window,
  not an absolute guarantee.
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
