# Phase 2 Review — Credential vault

> Independent review of Phase 2 against CLAUDE.md, ROADMAP.md, phase-2.md,
> THREAT-MODEL.md and the Phase-1 contracts. Findings only — no fixes applied.
> Ordered by severity. Reviewed at commit `305cc81`, across three independent
> passes (envelope crypto; KEK rotation and key custody; never-log / never-return
> / audit). Findings corroborated by more than one pass are marked.

## What holds up

The crypto core is sound, and that matters because it is the part hardest to fix
later. AES-256-GCM with a fresh 96-bit CSPRNG nonce per seal and no reuse path,
a full 128-bit tag, correct and complete envelope bounds checking (no malformed
input produces an out-of-range read), and no key-layer confusion between the KEK
and DEK envelopes. Decrypt failure is **not an oracle**: wrong key and tampered
ciphertext converge on the identical exception, and the structural checks that
differ run before any key-dependent computation. `PinnedBuffer` genuinely pins
(`GCHandleType.Pinned`), zeroes with `CryptographicOperations.ZeroMemory`, in
the right order, idempotently. `ResolvedCredential` is structurally
un-returnable — `Secret` is a `ReadOnlySpan<byte>`, so a serializer physically
cannot reach it — with a hand-written redacted `ToString()`.

Key-version selection is correct and fails loud: each DEK carries `key_id`,
unwrap passes it through, and a missing version throws rather than falling back
to current. Old KEK versions are retained, which is what makes every crash point
*inside* `RotateAsync` recoverable. RLS is pool-safe and fail-closed, and no
vault code passes secret material to a logger — all four log sites carry ids,
kinds and counts only.

Rotation's headline claim is properly tested: `KekRotationTests` asserts
credential envelopes are byte-for-byte identical before and after, and
re-resolves both tenants' secrets afterwards. That is a real proof, not a smoke
test.

The problems are in what surrounds that core — how it is wired, how it survives
partial failure, and how much of the "never logged" story the tests actually
establish.

---

## CRITICAL

### C1. Rotation runs under RLS in production DI and silently rotates nothing

*(**Resolved** — sanctioned per-tenant system scope, no elevated role; see ADR 0014.)*

**Files:** `src/Modules/Vault/VaultModule.cs:55`;
`src/Modules/Vault/Vault/KekRotationService.cs:29-40`;
`src/Infrastructure/Persistence/PersistenceModule.cs:16-28`.

`IKekRotationService` is registered `AddScoped` against the standard
`AppDbContext`, which is bound to the restricted `patchmgmt_app` connection and
carries `RlsConnectionInterceptor`. `IKekRotationService.cs:5-8` asserts the
opposite — "it runs under a maintenance DB context that is not restricted by
per-tenant RLS". **No such context exists in DI.** There is one `AddDbContext`
in the whole tree and one connection string.

Off the HTTP path there is no tenant GUC, so the policy fails closed:
`db.DataKeys.Where(...)` returns zero rows, `SaveChangesAsync` is a no-op, the
audit loop iterates an empty set, and the method returns
`KekRotationResult(newKeyId, 0, 0)` — a success. A new KEK version is minted and
persisted while **every existing DEK stays wrapped under the old one**.
Post-incident "we rotated the KEK" would be false. Invoked *with* a tenant set,
it rotates exactly one tenant and reports success.

The test does not catch this because `VaultTestHarness.Rotation()` hand-builds
the service over an owner-role context that DI never produces. The test proves
the algorithm; it proves nothing about the shipped wiring. This is the concrete
realization of Phase-1 **M6**.

### C2. Two processes sharing the key file destroy each other's KEK versions

*(**Resolved** — cross-process lock + reload-under-lock; see ADR 0015.)*

**Files:** `src/Modules/Vault/KeyProviders/SoftwareKeyProvider.cs:17,51-53`;
`KeyFileKekSource.cs:42-62`; `KekKeyset.cs:46-55`.

`_keyset` is loaded once and cached for the process lifetime — no reload, no
invalidation, no mtime check — and `SaveAsync` writes the **complete cached
snapshot** over the file. With two instances on a shared key-file volume (an API
pod plus a worker, say): A rotates → file is `{k0,k1}`; B still holds `{k0}` and
every resolve on B now throws `KeyNotFoundException` (a hard outage); B later
rotates → writes `{k0,k2}`, **erasing k1**. Every DEK at `key_id=k1`, and every
credential under it, is permanently unrecoverable. `_gate` serializes within one
process only; there is no file lock, lease, or read-modify-write.

### C3. The key file is renamed into place without an fsync

*(**Resolved** — flush-to-disk, atomic rename, directory fsync; see ADR 0015.)*

**File:** `src/Modules/Vault/KeyProviders/KeyFileKekSource.cs:53-61`.

Temp-then-rename is the right shape, but `File.Create` + serialize flushes to
the OS page cache only — no `Flush(flushToDisk: true)`, no `WriteThrough`, no
directory fsync. The classic rename-without-fsync pitfall: rename metadata can
be durable while the file's data is not. A power loss seconds after rotation can
leave a zero-length `kek.json` — **the KEK for every tenant is gone, and every
credential in the product is unrecoverable.** One unreplicated file, no escrow,
no backup hook.

### C4. A new KEK becomes the in-memory current before it is durably persisted

*(**Resolved** — the keyset is republished only after the durable write returns; see ADR 0015.)*

**File:** `src/Modules/Vault/KeyProviders/SoftwareKeyProvider.cs:51-53`.

`AddNewCurrent()` mutates the cached keyset and sets `CurrentKeyId` *before*
`SaveAsync`, which can throw (ENOSPC, EACCES, read-only mount). There is no
rollback. New tenant DEKs are then wrapped under a KEK that exists only in RAM
and are unrecoverable after restart — silently, until the restart.

---

## HIGH

### H1. AES-GCM is used with no associated data — an envelope is not bound to its row

*(Corroborated by two passes. **Resolved** at `ca54bec`; see ADR 0013.)*

**Files:** `src/Modules/Vault/Crypto/AesGcmEnvelope.cs:45,69`.

Both layers used the 4-argument AEAD overloads, so no ciphertext was bound to
the row storing it. An adversary with DB write access copies tenant A's
`credentials` row **and its `data_keys` row** into tenant B; RLS and the
composite FK are both satisfied; a legitimate B operator resolves it and
receives A's plaintext. The attacker never needs the KEK — the application is
the decryption oracle. Verified by writing the test to assert the attack
*succeeds*, and watching it pass.

### H2. The key file is created at default permissions and hardened afterwards

*(Corroborated by two passes. **Resolved** — created 0600 via `UnixCreateMode`; see ADR 0015.)*

**File:** `src/Modules/Vault/KeyProviders/KeyFileKekSource.cs:55-61,66-78`.

Order is create → write every KEK version → `HardenPermissions` → move. Between
create and harden the complete base64 KEK sits at the process umask (typically
world-readable) at a fully predictable `.tmp` path, and `File.Create` follows
symlinks. If serialization throws, a partial world-readable KEK file is left
behind, never hardened and never deleted.

### H3. The redaction belt scrubs the formatted string only; structured state is forwarded raw

*(**Accepted, documented and fenced** — not scrubbed. A sentinel-based state scrubber would be inert
(nothing registers a sentinel at runtime by design) and type-based filtering would have to redact
every string. ADR 0012 decision D records the corrected scope; `StructuredStateChannelTests` pins
both the boundary and the primary guarantee on this channel. Note the finding's severity: the channel
is unguarded, but all five vault log call sites pass only ids, enums and counts, so nothing leaks
through it today.)*

**File:** `src/Modules/Vault/Logging/SecretRedactingLoggerProvider.cs:104-115`.

`state` is passed to the inner sink verbatim; only the formatter delegate is
wrapped. Every structured sink reads `state` as key/value pairs and renders the
**raw parameter values**, and most never invoke the formatter. Reproduced
against real in-box sinks with the sentinel registered: `AddJsonConsole` emits
the secret twice inside `State`, and `EventSourceLoggerProvider` — registered by
`CreateBuilder` in this host and wrapped by the belt — emits it in
`[MessageJson]` while `[FormattedMessage]` shows `***REDACTED***`. An operator
running `dotnet-trace` or `dotnet-monitor` captures plaintext while stdout looks
clean. ADR 0012 claims two covered channels with scope state as the only known
third; structured state is a fourth, is what production sinks actually read, and
was undocumented.

### H4. No test can observe the structured channel

**File:** `tests/PatchManagement.Vault.Tests/Support/CapturingLoggerProvider.cs:28-35`.

The harness behind every never-log test records only `formatter(state, exception)`
plus `exception.ToString()`. So `VaultLoggingWiringTests` logging
`"vault op failed {Value}", secret` and asserting absence **passes for the wrong
reason**. A `byte[]` secret would also pass, rendering as `System.Byte[]` through
the formatter — which is the premise ADR 0012 decision C rests on, and it is a
property of `string.Format`, not of destructuring sinks.

### H5. The belt is silently removable and silently duplicable by ordinary logging config

**File:** `src/Modules/Vault/Logging/SecretRedactionRegistration.cs:25-44`.

Verified against a real `WebApplicationFactory`: `builder.Logging.ClearProviders()`
— the first line of every Serilog/OTel setup — drops the provider count to zero
with no error and no failing test. `AddConsole()` after `AddModules` adds a
**fifth, unwrapped** provider, because the decorated descriptor's implementation
type collapses to `object` and defeats `TryAddEnumerable` dedupe. No test
exercises the real host's provider list.

### H6. A resolve concurrent with a rotation races on a non-thread-safe Dictionary

*(**Resolved** — `KekKeyset` is immutable and republished by reference swap; see ADR 0015.)*

**Files:** `src/Modules/Vault/KeyProviders/KekKeyset.cs:16,40-52`;
`SoftwareKeyProvider.cs:29,36`.

`KekKeyset._keys` is a plain `Dictionary`. `AddNewCurrent()` writes under the
provider's gate, but `Get()` is called from `Wrap`/`Unwrap` **outside** it, on
arbitrary request threads. A `TryGetValue` racing a resize can spin, throw, or
observe a torn bucket array. The design intends resolve-during-rotation to be
safe; the implementation has an unsynchronized data race on exactly that path.

### H7. The default KEK path is container-ephemeral storage

**File:** `src/Modules/Vault/VaultModule.cs:67-68`.

Default is `AppContext.BaseDirectory/vault/kek.json` — inside the app's own
output directory. Compose persists `pgdata` and `redisdata` only. A container
rebuild or `down && up` destroys the KEK while Postgres durably keeps the
credentials it protects.

### H8. KMS providers fail at first use, not at startup

**Files:** `src/Modules/Vault/VaultModule.cs:34-41,71-79`.

`VAULT_SOFTWARE_KEK_SOURCE=operator|tpm` throws during `AddVaultModule` — fail
fast. But `VAULT_KEY_PROVIDER=azure|aws|hashicorp` registers a singleton that
throws only when called: the app boots green, passes `/health`, and throws on the
first credential operation in production. The *typo* case fails safer than the
plausible-misconfiguration case. Throwing rather than returning fake ciphertext
is right; the timing is the defect.

---

## MEDIUM

**Memory hygiene.** `secretCopy` is orphaned un-zeroed if the audit insert throws
or `ct` fires between the copy and the `ResolvedCredential` construction —
routine on request abort *(corroborated)*. DEK and credential plaintext stay live
across DB round-trips, contradicting "zeroed immediately after".
`ResolvedCredential.Dispose` uses `Array.Clear` where `CryptographicOperations.ZeroMemory`
is used two files away. **KEK material gets weaker hygiene than the DEKs it
protects** — base64 `string`s on every load and save, unpinned, never zeroed,
singleton lifetime *(corroborated)*. `PinnedBuffer` pins against GC relocation but
does not lock pages, so plaintext stays swap- and coredump-visible against
THREAT-MODEL:56-57.

**Audit.** Failed decrypts produce **no** audit record *(corroborated)* — tag
mismatch, missing KEK version and corrupt envelope all propagate silently, so
probing leaves no trail, which is the one class of event most needing detection.
`ListAsync` is unaudited. Audit rows are written after the commit, outside any
transaction. `SystemVaultActor.Name` is the constant `"vault"`, so "attributable"
is not achieved.

**Correctness and tests.** Vault queries carry no tenant predicate and rely wholly
on RLS (latent cross-tenant DEK merge if ever handed an owner context — and the
codebase does construct that shape). Rotation's `DeksRewrapped` counts skipped
DEKs, violating §4.6 "no unexplained numbers". Old KEK versions are **never**
retired despite phase-2.md:40 saying they are, so a future cleanup commit is a
data-loss commit. Retired DEKs are excluded from re-wrap. Rotation is one
unbounded transaction across all tenants with no batching or resumability, and
after ADR 0013 a single poisoned row aborts the whole sweep. The key file is not
validated on read (no length check, no MAC). `NeverReturnContractTests` is
one-assembly, `byte[]`-only, properties-only — `Credential.Envelope` and
`DataKey.WrappedDek` are public `byte[]` on entities it never scans. EF
`EnableSensitiveDataLogging` is correctly off but nothing pins it. Exceptions
escaping the vault are logged by ASP.NET **outside** the belt's category scope
with the inner chain intact.

**Judgements against ADR 0012.** The scope-state exemption is under-rated: it is
justified by a grep of one directory, but `IExternalScopeProvider` is
process-wide, so a scope created by the host or a Phase-3 connector renders on
vault log lines. And `RedactedException` is currently **net-negative** — with
`Register()` permanently uncalled, `Scrub` is the identity function, so the only
live effect is destroying `InnerException`/`Data` at the moment an operator needs
them.

---

## Wiring (found while reviewing, fixed at `a50d9ec`)

`PatchManagement.Api` did not reference `PatchManagement.Vault`, so
`PatchManagement.Vault.dll` never reached the host output and `CompositionRoot`
never discovered `VaultRegistrar`. The **entire module was unreachable in
production**, including the redaction belt. Several findings above (C1, H8) were
latent only because nothing loaded.

---

## Exit-criteria verdict

| Criterion | Verdict |
|---|---|
| Software provider round-trips a credential | **Met** — genuine end-to-end test against real Postgres under the restricted role |
| KEK rotation re-wraps DEKs without re-encrypting credentials | **Algorithm proven; product not** (C1) |
| Decryption in-memory only | **Not established** — tests prove "not in the DB row" and "not in logs"; nothing tests zeroing, pinning, or the exception path |
| Provider swappable via config, no caller changes | **Not established** — no test sets `VAULT_KEY_PROVIDER`; three of four are stubs |
| Never-log / never-return **with tests proving them** | **Not met** — never-log demonstrated on two paths, and the belt is proven only against a harness that cannot see the channel where it fails (H3/H4). Never-return is **vacuous**: there are no vault endpoints |
| Every credential access audited | **Partially** — success paths tested; silent on failed decrypts and `ListAsync` |
