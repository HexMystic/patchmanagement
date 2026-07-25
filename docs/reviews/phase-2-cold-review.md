Verification complete. Suite is green (66/66), and I ran the code on Windows, glibc Linux, and musl Linux.

# Key custody & rotation review — `phase/2-vault`

## HIGH

### H1. `KekRotationResult.Complete` reports `true` for a rotation that left live DEKs un-converged

`KekRotationResult.cs:39-40`:

```csharp
public bool Complete =>
    Failures.Count == 0 && TenantFailures.Count == 0 && TenantsAttempted == TenantsTotal;
```

`DeksSkipped` is not in that expression. Its own doc says *"True only if every tenant was swept and **every DEK converged**."*

`skipped++` fires at `KekRotationService.cs:93-97` for rows that **already matched** `RetiredAt == null && KeyId != targetKeyId` — i.e. live DEKs on a non-target KEK version — but have `WrappedDek is null || KeyId is null`. Those columns are nullable in the schema (`db/schema.sql:193-200`: `wrapped_dek bytea`, `key_id text`, no `NOT NULL`), so the row is representable, and the threat model's DB-write adversary produces it with a single `UPDATE data_keys SET wrapped_dek = NULL`.

Result: rotation returns `Complete = true`, the operator (following the type's own doc) does not re-run `CompleteRotationAsync`, and the chosen DEKs stay pinned off the target key. An adversary can select which DEKs escape a post-breach rotation, and the rotation says it worked.

The phase-2 review caught the earlier form ("`DeksRewrapped` counts skipped DEKs"). Splitting the counters fixed the number and moved the dishonesty into `Complete`.

### H2. Two concurrent rotations in one process both report `Complete` and can converge the estate back onto a superseded key

`KekRotationService` is a singleton (`VaultModule.cs:58`) with **no** concurrency guard. The only lock in the module is `SoftwareKeyProvider._gate`, which covers minting — not the sweep.

- Rotator A calls `RotateAsync`, mints v2, begins sweeping toward v2.
- Rotator B calls `RotateAsync`, mints v3, sweeps toward v3, finishes.
- A reaches its remaining tenants and writes **v2** over rows B already moved to v3.
- Both return `Complete = true`. The estate is split, and part of it sits on the older version.

The damaging ordering is the breach case: if v2 is the leaked key and the operator rotates to v3, a still-running earlier sweep re-pins rows *back onto the leaked v2* — and reports success.

This matters beyond the bug itself because **ADR 0016 defers exactly this finding on a premise that does not hold.** It dispositions "C-A residual" as multi-process-only: *"Stated in the name. With one process there is no other rotator."* One process supports two concurrent rotators. A finding parked for Phase 15 on multi-process grounds bites the single-process topology ADR 0016 declares supported.

## MEDIUM

### M2. Attacker-controlled blob length drives an unbounded **pinned** allocation before authentication

`SoftwareKeyProvider.cs:57-59` and `VaultCredentialProvider.cs:114-115`:

```csharp
var length = AesGcmEnvelope.PlaintextLength(wrappedDek);  // blob.Length - 29, no ceiling
using var plaintext = new PinnedBuffer(length);           // allocates AND PINS
var written = AesGcmEnvelope.Open(...);                   // tag check happens here
```

Measured against the real code:

```
  64 MiB blob -> AuthenticationTagMismatchException; allocated ~64 MiB,  43ms
 512 MiB blob -> AuthenticationTagMismatchException; allocated ~512 MiB, 460ms
```

`credentials.envelope` and `data_keys.wrapped_dek` are unconstrained `bytea`, and the DB-write adversary is named in the threat model. Because `PinnedBuffer` pins, oversized buffers pin the LOH and degrade the whole process, not just the request. A sane ceiling exists and isn't applied — a wrapped DEK is always exactly 61 bytes.

### M3. `Complete` cannot distinguish "swept everything" from "saw no tenants"

With `TenantsTotal == TenantsAttempted == 0` and no failures, `Complete` is `true` and `DeksRewrapped` is `0`. That is precisely the C1 failure mode the type exists to prevent — *"a rotation that silently did nothing must not be indistinguishable from one that worked"*. Today the registry read is sound (`tenants` has no RLS and is granted SELECT to `patchmgmt_app`, `db/schema.sql:837`), so nothing triggers it; the defect is that nothing would *detect* it if a future RLS policy, role change, or scoping bug made `ListTenantsAsync` return empty. Cancellation before the first tenant of an empty registry lands in the same hole.

### M4. Retired DEKs are excluded from convergence but not from `Complete`

`KekRotationService.cs:82` filters `RetiredAt == null`. Nothing in the codebase sets `RetiredAt` today, so this is latent — but the moment DEK retirement ships, rotation will leave retired DEKs (and the credentials that `ON DELETE RESTRICT` keeps alive under them) pinned to the old KEK while reporting `Complete = true`. `KekRotationResult` does not even carry a count of what was excluded.

### M5. Sweep accounting depends on an implementation detail the contract does not promise

`rewrapped`, `skipped`, and `failures` (a plain `List<T>`) are mutated from inside the `SweepAsync` callback. `ITenantScopeFactory.SweepAsync` (`ITenantScopeFactory.cs:37-38`) promises only "run work once per tenant, each in its own scope" — never sequential execution. `KekRotationService.cs:70` documents the *implementation* ("runs tenants sequentially"), not the *contract*. Parallelising the sweep — the obvious move at the 10,000-endpoint target — silently corrupts every count and races `List<T>.Add`.

### M6. `FsyncDirectory` is documented as best-effort but implements no exception handling — and the recorded reason for deferring the fix does not reproduce

`KeyFileKekSource.cs:241-254` has no try/catch. Its doc claims *"a failure here is not fatal … so it does not fail the rotation."* ADR 0015 carries a correction admitting the code doesn't match, and defers the ~3-line fix to Phase 15 on the grounds that `DllImport("libc")` *"on **musl** … can throw `DllNotFoundException`."*

**That premise doesn't hold.** I ran the declaration verbatim and the full write path on .NET 9:

| Platform | `DllImport("libc")` open/fsync/close | 8 concurrent cross-process rotations |
|---|---|---|
| Alpine 3.24 (musl, x64) | resolves; fd valid, `fsync` → 0 | all pass |
| Debian 12 (glibc, x64) | resolves; fd valid, `fsync` → 0 | all pass |

So the severity recorded in ADR 0015/0016 is overstated. The code/doc mismatch is still real and unguarded: any throw from those three calls escapes `WriteDurablyAsync` **after `File.Move` has committed**, leaving disk advanced while the caller is told the rotation failed. Separately, `fsync`'s return value is discarded — an `EIO`, the one failure the call exists to catch, is swallowed with no log, silently degrading the durability chain the class doc states unconditionally.

### M7. `VAULT_SOFTWARE_KEK_INIT` has no one-shot semantics, and the refusal message instructs operators to set it

The ephemeral default path (`VaultModule.cs:70-71`, `AppContext.BaseDirectory/vault/kek.json`) is recorded as H7. What isn't: `allowInitialize` is an ordinary env var read once into a singleton (`VaultModule.cs:77`), and `NotInitialized()` actively tells the operator to *"set `VAULT_SOFTWARE_KEK_INIT=true` once"*. Nothing makes them unset it. A compose file that keeps it set turns every future failed volume mount into a silent fresh-KEK mint — the exact CR-1 scenario the flag exists to prevent, with the guard disarmed by its own remediation instruction.

## LOW

- **L1.** `VaultCredentialProvider.ResolveAsync` never asserts `credential.TenantId == tenant.TenantId`. The AAD is derived entirely from the row, so it authenticates the row against itself. The relocation guarantee still holds (see below) — but the binding contributes **zero** defense-in-depth if the tenant GUC is ever wrong, since every value it checks would be self-consistent.
- **L2.** `AcquireLockAsync` (`KeyFileKekSource.cs:196-206`) treats every `IOException` as contention. A wrong path, a permissions problem, or a full disk spins for the full 30 s and then throws `TimeoutException("…Another process may be rotating, or a stale lock is held.")` — a misleading diagnosis on the one path where an operator is already under pressure.
- **L3.** `ReadFileAsync` (`KeyFileKekSource.cs:102-113`) validates nothing: no length check on the decoded base64 (a 16-byte KEK loads fine and only fails later at `CopyKeyTo` as an `ArgumentException` about destination size), no MAC over the file.
- **L4.** Rotation has no production trigger. Nothing in `src/` references `IKekRotationService` except the DI line. C1 fixed the wiring; nothing in the shipped host can start a rotation.

## Claims that do hold (pressure-tested, not taken on the docs' word)

- **Cross-process KEK custody — verified, on all three platforms.** ADR 0015 calls this "argued, not test-proven" and ADR 0016 defers it (M-1) as needing a harness the repo lacks. I built one. Eight genuine OS processes rotating one key file simultaneously: 9/9 versions on disk, no version lost, seed survived, `current` is one of the minted, all versions loadable by a fresh source. The sidecar lock genuinely excludes (contender waited 3.2 s for a 3 s holder). Identical results on Windows, glibc Linux, and musl Linux. **This is stronger than the repo believes it is.**
- **No write path can lose a KEK version.** Every `WriteDurablyAsync` call takes a keyset derived from a fresh under-lock disk read (`AddVersionAsync`) or is gated on the file being absent (`LoadOrInitializeAsync`). The "load, mutate, save" shape is genuinely gone.
- **Absence is fatal.** `ReadAsync` and `AddVersionAsync` both throw on a missing store and mint nothing, even with `allowInitialize: true`.
- **The deep-copy claim (H-1) is real.** Zeroing a `Snapshot()` result does not destroy the live KEK; parent and child keysets share no arrays.
- **Envelope relocation fails.** Cross-tenant and cross-row both give `AuthenticationTagMismatchException`. An envelope cannot be relocated across tenants and still decrypt — relocating requires rewriting `tenant_id` to satisfy RLS, which breaks the AAD.
- **No version downgrade.** Forcing the version byte to `0x01` or `0xFF` gives `CryptographicException`, not acceptance.
- **"No elevation / cannot become a cross-tenant bypass" holds.** `FORCE ROW LEVEL SECURITY` on every tenant table, USING *and* WITH CHECK policies, `NULLIF(current_setting('app.tenant_id', true), '')` failing closed on an unset GUC; `tenants` carries no tenant data and is SELECT-only to the app role; `TenantContextAccessor` and `RlsConnectionInterceptor` are both scoped and `AddDbContext`'s `IServiceProvider` overload defaults `optionsLifetime` to Scoped, so each `TenantScope` gets its own interceptor. No raw `NpgsqlConnection`, `GetDbConnection`, `FromSqlRaw`, or Hangfire path exists to bypass the interceptor. The sweep is what it claims: N single-tenant scopes, no "all tenants" mode.

Two things I'd flag about the *documents* rather than the code: ADR 0016's deferral table rests on the multi-process premise in H2, which is false for concurrent in-process rotations; and its H-3 row rests on the musl premise in M6, which does not reproduce. Both deferrals need re-deriving on accurate grounds.
