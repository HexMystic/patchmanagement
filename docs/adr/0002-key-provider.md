# 2. Pluggable IKeyProvider with a software default

- **Status:** Accepted
- **Date:** 2026-07-24

## Context
The vault needs a master key (KEK). Requiring a cloud KMS would break on-premises
and air-gapped deployments — which are our highest-value customers. But enterprises
that *do* run a KMS (Azure Key Vault, AWS KMS, HashiCorp Vault) expect to use it.

## Decision
Define **`IKeyProvider`** as the custody abstraction. Ship a **`SoftwareKeyProvider`
as the default** (KEK from a local cold-start source — key file / operator / TPM),
so the product works out of the box with zero external dependency. Provide opt-in
`AzureKeyVault`, `AwsKms`, and `HashiCorpVault` providers selected purely by config.

Envelope encryption is mandatory: KEK wraps per-tenant DEKs; DEKs encrypt
credentials. **KEK rotation re-wraps DEKs only — credentials are never re-encrypted.**

## Consequences
- Out-of-the-box on-prem/air-gapped support; enterprises plug in existing KMS.
- The software provider's KEK cold-start is a real risk surface — documented and
  mitigated in `docs/THREAT-MODEL.md`.
- Rotation is cheap and zero-downtime because only DEKs are re-wrapped.

## Rejected
- **Cloud KMS required** — kills on-prem/air-gapped deals.
- **HashiCorp Vault mandatory** — forces an extra service on every customer.
