# 24. The discovery natural key is a reachability coordinate, not a machine identity

- **Status:** Accepted
- **Date:** 2026-08-26
- **Relates to:** CLAUDE.md §4.5 (frozen contracts) and **NEVER #6**, [ADR 0006](0006-multitenancy-rls.md)
  (tenancy), [ADR 0003](0003-cloud-agnostic-connector.md) (host/port is configuration),
  HARD-PROBLEMS **#6** (idempotency) and **#10** (roaming devices), Phase 4 exit criteria **(c)** and
  **(h)**
- **Applies to:** `assets.endpoint_port` (new column), `ux_assets_discovery_candidate` (new partial
  unique index), and every discovery upsert in `src/Modules/Discovery`
- **Supersedes nothing.**

## Context

Phase 4 criterion (h) requires a re-run of the same sweep to write **the same rows with stable ids**,
not merely to avoid duplicates. That needs a natural key on `assets`, and `assets` has none:
`ix_assets_tenant_id_hostname` is **non-unique**, and the only unique things on the table are the
surrogate `id` and the `(tenant_id, id)` alternate key that exists to be a composite FK target.

**This is therefore an edit to a frozen table**, not an additive one, which is why it gets an ADR
before a migration rather than a note at phase close.

### The premise that decides everything else

**A sweep cannot establish machine identity.** It opens a TCP connection and observes that something
answered. It does not log in, so it cannot read `/etc/machine-id`, an SMBIOS UUID, or any other
durable identifier — that requires a credential and a session, which is slice 3 (inventory).

Every candidate key available at sweep time is therefore an *address*. The question is not "which key
identifies the machine" — none of them does — but **which address-shaped key fails in the direction
we can live with**.

### What was rejected, and why

**`(tenant_id, hostname)`.** Discovery does not know the hostname; it is unknown until something logs
in and asks. `hostname` is `NOT NULL`, so every candidate would need a fabricated value — most
naturally the IP address, which makes the column lie about what it holds. Renames also fork the row,
producing a second asset for a machine that only changed its name.

**`(tenant_id, ip)`.** Rejected on two independent grounds, and the second is the serious one.

1. **It breaks against our own lab.** The five distro containers are published on `127.0.0.1` at
   ports 2201–2205. Keyed on IP alone they collapse into **one** asset, and criterion (c) — "the
   sweep finds the 5 lab containers" — becomes unprovable by construction.
2. **DHCP reassignment makes it actively wrong in production.** When a machine's lease moves, the
   next machine to receive that address **inherits the previous machine's asset row**, along with its
   inventory, its findings and its compliance history. That is a silent merge of two hosts, and it is
   the failure mode HARD-PROBLEMS #10 is circling when it insists reachability and `last_seen` be
   modelled honestly.

## Decision

**A discovery candidate is keyed by the coordinates it was reached at:**

```sql
ALTER TABLE public.assets ADD COLUMN endpoint_port integer NULL;

CREATE UNIQUE INDEX ux_assets_discovery_candidate
    ON public.assets (tenant_id, ip, endpoint_port)
    WHERE source = 'discovery' AND ip IS NOT NULL AND endpoint_port IS NOT NULL;
```

Three properties, each deliberate.

**`endpoint_port` is a new column because the port is load-bearing, not decoration.** It is also
already part of how this system addresses an endpoint: `EndpointTarget` carries `Host` and `Port`
(ADR 0003), so the asset table now records the coordinate the connector will actually use rather than
half of it. It is nullable, because an asset that arrived from AD, DHCP or an import has no port.

**The index is PARTIAL, scoped to `source = 'discovery'`, because the key is only valid for the
pre-identity state.** Once inventory establishes a durable machine id, *that* becomes the arbiter and
this index stops being one — the row leaves the predicate as its provenance changes. Encoding that as
a partial index rather than a table-wide constraint is what keeps a temporary key from silently
becoming a permanent one.

**Where it must fail, it over-splits.** A Windows host answering on both 5985 and 5986 produces
**two** candidate rows for one machine.

## Consequences

**The accepted cost, stated plainly: one machine can appear as several candidates.** We prefer that,
in one direction and for one reason — **a redundant row is recoverable and a merged row is not.**

- Over-splitting produces a duplicate that slice 3 resolves the moment it can read a durable machine
  id, and until then the duplicate is *visible*: two rows at the same IP, plainly odd.
- Over-merging destroys information with no signal at all. Two machines become one row, one of them
  vanishes from the estate, and the compliance denominator shrinks silently. `DIFFERENTIATORS.md`
  §2's whole claim is that coverage gaps are the risk we surface; a key that manufactures them would
  undercut the feature it serves.

This is the same asymmetry the sweep already applies elsewhere: an out-of-scope range refuses the
whole request rather than sweeping part of it, and a range that cannot be bounded is refused by name
rather than truncated.

**`assets` is empty in dev (0 rows), so the index applies cleanly here.** That is a fact about this
checkout, not a general one. Any environment holding rows must be checked for `(tenant_id, ip,
endpoint_port)` duplicates among `source = 'discovery'` rows before this migration will apply.

**Retirement remains a state, not a `DELETE`.** Nothing here changes that; it is worth restating
because a stale candidate at a reassigned address is exactly the row someone will want to delete, and
the `RESTRICT` foreign keys from `asset_evidence` will refuse while its evidence stands.

## When to revisit

- **When slice 3 lands a durable machine id.** That is the trigger to add `assets.machine_id` with
  its own per-tenant unique index and to demote this one to what it always was: the key for a
  candidate nobody has logged into yet. The merge path — collapsing two candidate rows onto one
  machine id — belongs with that work, and is deliberately not half-built now.
- **If a sweep ever needs to record more than one port per candidate.** The answer then is a child
  table of observed ports, not a wider unique index; widening the key would multiply rows further in
  precisely the case the key exists to bound.
- **If Phase 6 or 8 ever needs to join an asset by address alone**, that is the signal that address
  and identity have been conflated somewhere downstream, and this ADR is the thing to re-read.
