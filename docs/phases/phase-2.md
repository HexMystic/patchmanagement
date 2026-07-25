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
    Task<byte[]> WrapAsync(byte[] dek, string keyId, KeyBinding binding, CancellationToken ct);
    Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, KeyBinding binding, CancellationToken ct);
    Task<string> RotateMasterKeyAsync(CancellationToken ct); // returns new keyId
}
```
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
- `RotateMasterKeyAsync` creates a new KEK version, re-wraps every DEK with it,
  updates `dek.key_id`, retires the old version. **No credential row is touched.**
- DEKs carry `key_id` so unwrap always selects the right KEK version → zero-downtime
  rotation.
- **Tenancy** — rotation runs off the HTTP path, where nothing sets a tenant. It sweeps
  tenants one at a time via `ITenantScopeFactory`, each scope under the ordinary
  restricted role with RLS enforced; there is no maintenance context and no elevated
  role ([ADR 0014](../adr/0014-system-tenancy-scope.md), review C1).
- **Isolation** — each DEK re-wraps in its own try/catch, so a corrupt or relocated row
  fails alone and is reported in `KekRotationResult.Failures` rather than aborting the
  sweep. Each tenant saves and audits in its own scope, so no transaction spans the estate.
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
never passes secret material to a logger. Three boundaries are accepted, not deferred:
- **No runtime caller for `Register()`.** Resolve-time self-registration is
  **rejected** — it would hold a non-zeroable plaintext string per resolved credential
  for the process lifetime, contradicting the in-memory-only invariant above. The
  filter takes process-lifetime literals only.
- **Log scope state is not scrubbed.** `BeginScope` state is forwarded unchanged;
  arbitrary `TState` cannot be rewritten. Accepted because nothing creates a
  data-carrying scope, and enforced by `VaultLoggingConventionTests`.
- **Records must not leak via a generated `ToString()`.** Secret-bearing types either
  are not records or override `ToString()` redacted; pinned by the same test.

Residual obligation is owned by **Phase 3 (Connectors)**: the belt covers vault log
categories only, so the NeverLog scan must be extended to the connector module.

## Data (extends Phase 1 `credentials`)
`credentials(envelope bytea, dek_id, kind, target_scope, ...)`,
`data_keys(id, tenant_id, wrapped_dek bytea, key_id, created_at, retired_at)`.

## Exit criteria
Software provider round-trips a credential; KEK rotation re-wraps DEKs without
re-encrypting credentials (proven by test); redaction + no-return contract tests
pass; provider is swappable via config with no code change to callers.
