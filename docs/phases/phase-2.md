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
    Task<byte[]> WrapAsync(byte[] dek, string keyId, CancellationToken ct);
    Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, CancellationToken ct);
    Task<string> RotateMasterKeyAsync(CancellationToken ct); // returns new keyId
}
```
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

## Invariants (with tests that prove them)
- **Decryption is in-memory only.** Plaintext lives in a pinned buffer, zeroed after
  use; never written to disk, cache, or log.
- **Never logged** (NEVER #1): a logging redaction filter + a test that scans emitted
  logs for known secret material and fails if found.
- **Never returned** (NEVER #2): credential DTOs expose metadata only (id, name,
  kind, scope) — never ciphertext or plaintext. A contract test asserts no vault
  endpoint serializes secret fields.

## Data (extends Phase 1 `credentials`)
`credentials(envelope bytea, dek_id, kind, target_scope, ...)`,
`data_keys(id, tenant_id, wrapped_dek bytea, key_id, created_at, retired_at)`.

## Exit criteria
Software provider round-trips a credential; KEK rotation re-wraps DEKs without
re-encrypting credentials (proven by test); redaction + no-return contract tests
pass; provider is swappable via config with no code change to callers.
