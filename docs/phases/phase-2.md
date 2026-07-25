# Phase 2 — Credential Vault (parallel)

> The vault stores privileged credentials for an entire fleet — the highest-value
> target in the customer's environment. Build it to the threat model
> (`docs/THREAT-MODEL.md`). A fresh session can execute this doc standalone.

## Objective
An envelope-encrypted credential store with a pluggable key-custody backend,
in-memory-only decryption, and hard never-log/never-return guarantees.

## Key hierarchy (envelope encryption)
```
Master Key (KEK)         ← held by IKeyProvider (never in the DB)
   └─ per-tenant Data Key (DEK)   ← stored WRAPPED (encrypted by KEK) in the DB
        └─ Credential ciphertext  ← encrypted by DEK (AES-256-GCM), stored in DB
```
Rotating the KEK re-wraps each DEK only — **credentials are never re-encrypted**.
Rotating a DEK re-encrypts that tenant's credentials (rare, explicit).

## `IKeyProvider` (custody is pluggable)
```csharp
public interface IKeyProvider
{
    Task<string> GetCurrentKeyIdAsync(CancellationToken ct);     // cached; cheap
    Task<string> RefreshCurrentKeyIdAsync(CancellationToken ct); // authoritative; re-reads the store
    Task<byte[]> WrapAsync(byte[] dek, string keyId, KeyBinding binding, CancellationToken ct);
    Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, KeyBinding binding, CancellationToken ct);
    Task<string> RotateMasterKeyAsync(CancellationToken ct);     // returns new keyId
}
```
The two current-key reads are distinct on purpose: sealing a **new** DEK, and choosing a
convergence target, must both be authoritative, or a process that did not perform the last
rotation works from a superseded version (re-review C-A, [ADR 0014](../adr/0014-system-tenancy-scope.md)).
`KeyBinding(Guid TenantId, Guid DataKeyId)` identifies the row a wrapped DEK belongs to, so a
relocated `data_keys` row fails to unwrap ([ADR 0013](../adr/0013-envelope-binding.md)). It is typed
rather than raw associated-data bytes because backends differ: the software provider uses AES-GCM
associated data, AWS KMS an `EncryptionContext`, HashiCorp Transit a `context` — and Azure Key
Vault's `wrapKey` has no such parameter at all, a limitation recorded on that provider.
Implementations:
- **`SoftwareKeyProvider` (default, on-prem/air-gapped)** — KEK from a cold-start
  source (`keyfile` default | `operator` | `tpm`; see THREAT-MODEL). Zero external
  dependency.
- `AzureKeyVaultProvider`, `AwsKmsProvider`, `HashiCorpVaultProvider` — opt-in;
  the KEK never leaves the KMS (wrap/unwrap happen there).

Selected via `VAULT_KEY_PROVIDER`. See `docs/adr/0002-key-provider.md`.

## Rotation & re-wrap (reviewers probe this first)
- `RotateMasterKeyAsync` creates a new KEK version, re-wraps every DEK with it, and
  updates `dek.key_id`. **No credential row is touched.**
- **Superseded KEK versions are RETAINED, deliberately — nothing retires or deletes one.**
  This line previously read "retires the old version", which the code has never done and must
  not do (re-review H-D2). Retention is load-bearing: a DEK not yet re-wrapped still unwraps,
  which is what makes every crash point inside a rotation recoverable and what
  `CompleteRotationAsync` relies on to converge stragglers. **Implementing the old wording would
  strand every unconverged DEK, and the credentials under them, permanently.** The safe version —
  a *retirement floor* that refuses superseded versions only once convergence is provably
  complete — is real work and belongs to **Phase 15**
  ([ADR 0016](../adr/0016-single-process-vault.md)); it is also what would close re-review M-6.
- DEKs carry `key_id` so unwrap always selects the right KEK version → zero-downtime
  rotation.
- **Tenancy** — rotation runs off the HTTP path, where nothing sets a tenant. It sweeps
  tenants one at a time via `ITenantScopeFactory`, each scope under the ordinary
  restricted role with RLS enforced; there is no maintenance context and no elevated
  role ([ADR 0014](../adr/0014-system-tenancy-scope.md), review C1).
- **Isolation** — each DEK re-wraps in its own try/catch, so a corrupt or relocated row
  fails alone and is reported in `KekRotationResult.Failures` rather than aborting the
  sweep. Each tenant saves and audits in its own scope, so no transaction spans the estate.
- **Key-file custody** — adding a KEK version is one atomic read-modify-write: an exclusive
  cross-process lock on a sidecar, a re-read from disk (so concurrent rotations are additive,
  never destructive), then flush-to-disk → atomic rename → directory fsync. It returns only
  once durable, and the in-memory keyset — immutable — is republished by reference swap only
  after that ([ADR 0015](../adr/0015-kek-file-durability.md), review C2/C3/C4).
- **An absent key store is an error, never first boot.** Only cold start may initialize, and only
  with `VAULT_SOFTWARE_KEK_INIT=true` — set once at first boot and unset again. Rotation and reload
  refuse outright: a missing store is usually a lost mount, and minting a KEK there strands every
  existing credential (re-review CR-1).
- **The convergence target is read authoritatively**, not from the process cache, so a host that did
  not perform the rotation cannot converge the estate backwards onto a superseded KEK (re-review C-A).
- **Resumability** — `CompleteRotationAsync` converges stragglers onto the *existing*
  current version without minting a new one. Retrying `RotateAsync` would mint a key per
  attempt; use it to start a rotation, `CompleteRotationAsync` to finish a partial one.

## Invariants (with tests that prove them)
- **Decryption is in-memory only.** Plaintext lives in a pinned buffer, zeroed after
  use; never written to disk, cache, or log.
- **Never logged** (NEVER #1): a logging redaction filter + a test that scans emitted
  logs for known secret material and fails if found.
- **Never returned** (NEVER #2): credential DTOs expose metadata only (id, name,
  kind, scope) — never ciphertext or plaintext. A contract test asserts no vault
  endpoint serializes secret fields.

## Accepted limitations (redaction) — see [ADR 0012](../adr/0012-log-redaction-scope.md)
The redaction filter is the **belt**; the primary guarantee remains that vault code
never passes secret material to a logger. **The belt covers two channels: the formatted message
text, and the exception object — the latter only when the belt is *armed*** (at least one
registered literal; unarmed it has no live effect at all, ADR 0012 decision E). **Four** boundaries
are accepted, not deferred:
- **No runtime caller for `Register()`.** Resolve-time self-registration is
  **rejected** — it would hold a non-zeroable plaintext string per resolved credential
  for the process lifetime, contradicting the in-memory-only invariant above. The
  filter takes process-lifetime literals only. Which means the belt is **inert in production
  today, by design** — read it as a thin secondary, never as the guarantee.
- **Structured log state is not scrubbed** — and it is the channel production sinks actually
  read. `TState` is forwarded to the sink verbatim; a JSON console, an OTel exporter or
  `EventSourceLoggerProvider` enumerates it as key/value pairs and emits the **raw values**, often
  without ever calling the formatter. A sentinel-based scrubber would be inert (nothing registers
  one at runtime, per the bullet above) and type-based filtering would mean redacting every string,
  destroying the diagnostics the channel exists for. What protects it is the primary guarantee: all
  five vault log call sites pass only ids, enums and counts. `StructuredStateChannelTests` pins
  **both** halves — the boundary (so silently starting to scrub it fails the build) and the
  guarantee (a real store/resolve puts no secret there, swept in four encodings). Added by ADR 0012
  decision D; this section previously said "three boundaries" and omitted it entirely (re-review
  H-D1).
- **Log scope state is not scrubbed.** `BeginScope` state is forwarded unchanged;
  arbitrary `TState` cannot be rewritten. Accepted because nothing creates a
  data-carrying scope, and enforced by `VaultLoggingConventionTests`.
- **Records must not leak via a generated `ToString()`.** Secret-bearing types either
  are not records or override `ToString()` redacted; pinned by the same test, which covers record
  classes **and** record structs (it detected only the former until re-review H-1).

Residual obligation is owned by **Phase 3 (Connectors)**: the belt covers vault log
categories only, so the NeverLog scan must be extended to the connector module.

## Data (extends Phase 1 `credentials`)
`credentials(envelope bytea, dek_id, kind, target_scope, ...)`,
`data_keys(id, tenant_id, wrapped_dek bytea, key_id, created_at, retired_at)`.

## Exit criteria — amended 2026-07-26
Software provider round-trips a credential; KEK rotation re-wraps DEKs without
re-encrypting credentials (proven by test); redaction + no-return contract tests pass.

**Amendment.** "Provider is swappable via config with no code change to callers", and with it the
opt-in Azure Key Vault / AWS KMS / HashiCorp Vault backends, **moves to Phase 15 (Key custody & KMS
providers)**. The three cloud providers ship as honest stubs that throw; the `IKeyProvider` seam
they plug into is delivered and exercised. This is a deliberate scope move recorded in
[ADR 0016](../adr/0016-single-process-vault.md), in the same shape as the C1 amendment to Phase 1 —
not a lowered bar. Phase 15 also owns making a misconfigured provider fail at **startup** rather
than on the first credential operation (review H8).

Two further verdicts, so the criteria are not read as silently met:
- **"Never returned"** is **vacuous by construction** at this phase — there are no vault endpoints
  to assert against. `NeverReturnContractTests` stands as far as it reaches (`ResolvedCredential` is
  structurally un-serializable). **Re-assert at Phases 12 and 14**, when a caller-facing surface
  first exists.
- **"Decryption in-memory only"** is met in substance: plaintext lives in a pinned, self-zeroing
  buffer, and since re-review H-1 the KEK does too. The memory-hygiene residue — the orphaned
  `secretCopy` on the cancel path, plaintext held across DB round-trips, `Array.Clear` vs
  `ZeroMemory`, no page-locking against swap or coredumps — remains recorded as Phase 2 hardening.
