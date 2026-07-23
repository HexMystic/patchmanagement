# THREAT-MODEL — The Credential Store

Agentless management means storing privileged credentials for an **entire fleet** in
one place. That store is **the highest-value target in the customer's environment** —
compromising it can mean domain-wide administrative control. This document defines
how we protect it and states, honestly, what a compromise does and does not expose.

## Assets & adversaries
- **Primary asset:** stored endpoint credentials (Windows admin, SSH keys, sudo).
- **Secondary:** the master key / KEK; per-tenant data keys; audit trail integrity.
- **Adversaries:** external attacker with DB access (stolen backup, SQLi, exfil);
  malicious/negligent insider with console access; attacker who compromises the
  running application host ("compromised console").

## Envelope encryption (defense in depth)
```
Master Key (KEK)  — custody outside the DB (IKeyProvider)
   └─ per-tenant Data Key (DEK)  — stored WRAPPED (KEK-encrypted) in the DB
        └─ Credential ciphertext — AES-256-GCM under the DEK, in the DB
```
- A database dump alone yields **only ciphertext and wrapped DEKs** — useless without
  the KEK.
- **Per-tenant DEKs** contain blast radius: compromising one tenant's DEK never
  exposes another tenant's credentials.
- **Rotation is cheap:** rotating the KEK **re-wraps DEKs only**; credentials are
  never re-encrypted (Phase 2). DEK rotation re-encrypts a single tenant, on demand.

## Master-key custody (pluggable; software default)
`IKeyProvider` abstracts custody (ADR 0002):
- **Software (default):** KEK held locally — works on-prem and **air-gapped** with no
  external dependency. Custody of the KEK is the software provider's cold-start
  problem (below).
- **Azure Key Vault / AWS KMS / HashiCorp Vault (opt-in):** the KEK never leaves the
  KMS/HSM; wrap/unwrap happen there. Strongest custody for customers who have it.

## The KEK cold-start problem (reviewers ask this first)
When the container restarts **unattended at 3am**, where does the KEK (or the
passphrase that unlocks it) come from? There is no free lunch:

| Source | Security | Unattended restart? | Notes |
|--------|----------|---------------------|-------|
| **Operator-entered on start** | Strongest — secret never at rest on the host | **No** — needs a human | Best for high-security / air-gapped tiers accepting manual starts |
| **Key file w/ locked-down perms** | Moderate — KEK at rest, protected by filesystem ACLs + OS | **Yes** | Convenient; weaker if the host FS is compromised |
| **TPM sealing** | Strong — KEK sealed to hardware/boot state | **Yes** (same host) | Hardware-dependent; not always available on target hosts/VMs |

**Recommended default:** **key file with strict permissions** for unattended on-prem
deployments (the common case), **operator-entered** for high-security/air-gapped
tiers that accept manual restarts, and **TPM sealing** where the hardware supports it.
The choice is explicit configuration (`VAULT_SOFTWARE_KEK_SOURCE`), and the tradeoff
is documented for the customer — never hidden. Enterprises that want none of these
plug in a KMS provider instead.

## In-memory-only decryption
- Credentials are decrypted **only in memory**, only at the moment of use, into a
  pinned buffer that is **zeroed immediately after**.
- Plaintext is **never** written to disk, cache, swap-visible structures, temp files,
  or logs. No decrypted secret is ever serialized.

## Hard guarantees (enforced, tested)
- **Never logged** (CLAUDE.md NEVER #1): a redaction filter on the logging pipeline +
  a test that fails if known secret material appears in emitted logs at any level.
- **Never returned by any API** (NEVER #2): credential DTOs carry metadata only
  (id, name, kind, scope). A contract test asserts no endpoint/event/error serializes
  ciphertext or plaintext.

## Compromised-console scenario (honest boundaries)
If an attacker gains code execution on the running application host **while it is
live**, they can, for the duration of that access, cause the app to decrypt
credentials it is entitled to use — no software design fully prevents a live,
privileged RCE from abusing the app's own legitimate capability. What our design
**does** guarantee:
- **Data at rest stays protected:** stealing the DB / backups yields only ciphertext;
  the KEK is not in the DB. With a KMS provider the KEK never resides on the host at
  all.
- **Blast radius is bounded per tenant** by per-tenant DEKs.
- **Everything is audited:** every decrypt/use of a credential is recorded in the
  append-only audit log (which never contains the secret), so abuse is detectable and
  attributable.
- **Rotation is fast:** post-incident, rotate the KEK (re-wrap DEKs) and rotate
  affected endpoint credentials; no bulk re-encryption bottleneck.
- **Least standing exposure:** decryption is just-in-time and memory-only, minimizing
  the window in which any plaintext exists.

We state plainly: protecting against a live compromised console is a matter of
*containment, detection, and fast rotation*, not a claim of impossibility. The
at-rest and cross-tenant guarantees are absolute; the live-RCE case is bounded and
observable.
