# 13. Envelopes are cryptographically bound to the row that stores them

- **Status:** Accepted
- **Date:** 2026-07-25
- **Amends:** the envelope wire format (version `0x01` → `0x02`) and the `IKeyProvider` shape
  published in `docs/phases/phase-2.md`
- **Context:** Phase 2 review finding H1

## Context

`AesGcmEnvelope` used the 4-argument AES-GCM overloads, so no ciphertext carried associated data.
`CredentialPayload` holds only `[usernameLen][username][secret]` — no binding data either. A sealed
envelope was therefore a free-floating blob: it decrypted under **any** row pointing at the key that
sealed it.

The attack, against an adversary THREAT-MODEL already assumes (external attacker with DB access, a
restored backup, a compromised DBA account):

1. Read tenant A's `credentials` row and the `data_keys` row it references.
2. Insert both into tenant B — a new `data_keys` row carrying A's `wrapped_dek`, and a new
   `credentials` row carrying A's `envelope` and pointing at it. Both stamped `tenant_id = B`.
3. RLS is satisfied (both rows say B) and the composite FK `(tenant_id, data_key_id)` is satisfied
   (the cloned DEK is B's).
4. A legitimate tenant-B operator resolves that credential. The KEK is global, so the DEK unwraps;
   the envelope authenticates; **tenant B receives tenant A's plaintext.**

The attacker never needs the KEK — the application is the decryption oracle. `THREAT-MODEL.md:86-87`
calls the cross-tenant guarantee "absolute"; it was RLS plus one foreign key, both living inside the
database the adversary is assumed to have compromised.

This was verified, not theorised: the test now asserting the attack fails was first written asserting
it **succeeds**, and it passed.

## Decision

Both envelope layers are bound to their row with AES-GCM associated data. `Seal`/`Open` take a
required `associatedData` parameter; there is no unbound overload to fall back to.

| Layer | Sealed under | Associated data |
|---|---|---|
| Credential envelope | the DEK | `patchmgmt:v2:credential\|{tenantId:N}\|{credentialId:N}\|{dataKeyId:N}` |
| Wrapped DEK | the KEK | `patchmgmt:v2:datakey\|{tenantId:N}\|{dataKeyId:N}` |

A canonical UTF-8 string, not packed bytes: it is auditable in a debugger and a log, and `Guid:N`
has one representation on every platform. The leading domain label keeps the two layers from ever
colliding, and `v2` ties the binding to the format version so a downgrade cannot be forged.

**`key_id` is excluded from the data-key binding.** Rotation rewrites `dek.key_id`, so a binding
containing it would differ between unwrap and re-wrap, and a shared helper called on both sides
would silently compute the wrong value. `keyId` already selects the KEK version. `retired_at` is
excluded for the same class of reason: retiring a row must never brick its unwrap.

**Row ids are minted before sealing.** Both are client-generated `Guid.NewGuid()` with no database
default, so this is a statement reorder in `VaultCredentialProvider.StoreAsync` and
`DataKeyService.GetOrCreateActiveAsync` — no behavioural change beyond the binding itself.

**Resolve rebuilds the binding from the row's own stored `tenant_id`, not the ambient tenant
context.** RLS makes them equal in normal operation; when they differ, that *is* the relocation, and
authentication fails.

**Version `0x02`; `0x01` is rejected outright.** No transitional read path: accepting unbound
envelopes would leave a permanent bypass of the property this ADR exists to establish. Verified safe
— the live cluster reports `credentials = 0` and `data_keys = 0` in both persistent databases, test
databases are created and dropped per run, and nothing seeds, caches, or fixtures an envelope. A
`0x01` blob fails with "Unsupported envelope version", deliberately **not** a tag mismatch, so an
operator can tell a format problem from a binding violation.

**`IKeyProvider.WrapAsync`/`UnwrapAsync` take a typed `KeyBinding(Guid TenantId, Guid DataKeyId)`**
rather than raw bytes, because the backends express binding differently — see Consequences.

## Consequences

- A relocated envelope or wrapped DEK raises `AuthenticationTagMismatchException` instead of
  decrypting. Cross-tenant containment becomes cryptographic rather than resting on RLS and one FK.
- The intra-tenant swap — pasting one credential's envelope onto another row in the same tenant,
  which had **no** foreign-key mitigation at all — now fails too.
- **Provider portability is uneven, and that is recorded rather than hidden.** AWS KMS maps
  `KeyBinding` onto `EncryptionContext`; HashiCorp Transit onto `context`. **Azure Key Vault's
  `wrapKey` has no associated-data parameter**, so an implementation there must bind by another
  means (e.g. sealing locally under a Key Vault-wrapped intermediate key) and must not silently drop
  the binding. Each stub's doc comment carries its own mapping.
- The envelope is **no longer self-describing**: decryption now requires the caller to supply the
  correct binding. The `AesGcmEnvelope` doc comment previously claimed the opposite and was corrected.
- **A poisoned or relocated `data_keys` row now aborts KEK rotation**, which walks every non-retired
  DEK. Failing loud is right, but one bad row blocking a whole rotation compounds the rotation
  robustness findings (no batching, no resumability) already recorded against Phase 2. Not addressed
  here.
- No schema migration: every binding component is an existing column.

## Rejected

- **Binding the credential layer only.** It defeats the described attack on its own, but leaves a
  wrapped DEK relocatable between tenants, and the defence would rest on a single layer.
- **Putting binding data inside the plaintext** (`CredentialPayload`). It would be encrypted rather
  than authenticated-only, forcing a decrypt before the mismatch could be detected, and it would
  change the payload format for no gain over AAD.
- **Raw `ReadOnlySpan<byte>` on `IKeyProvider`.** Fits the software provider and nothing else; AWS
  and HashiCorp take structured context, so the interface would have prejudged an implementation
  none of the stubs could honour.
- **Accepting `0x01` during a transition.** There is no data to transition, and it would keep an
  unbound code path alive permanently.
