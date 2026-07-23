# Phase 4 — Discovery & Inventory (parallel)

> Find endpoints, capture what's on them, and — critically — surface the machines
> that are on the network but in nobody's inventory. A fresh session can execute
> this doc standalone. Depends on Phase 3 (connector).

## Objective
Network discovery + per-host inventory via the connector, plus **unmanaged-asset
detection** (a designed-in differentiator).

## Discovery
- **Sweep** configured IP ranges/CIDRs (tenant-scoped) for reachable hosts and open
  management ports (22 / 5985 / 5986 / 445).
- Classify OS family from banner/probe before choosing a connector.
- Persist candidates into `assets` with `source = discovery`, `managed = false`
  until inventoried.

## Inventory (per managed host, over the connector)
- **Linux:** enumerate installed packages + versions via the package manager
  (`dpkg-query` / `rpm -qa`), kernel, OS release. Store into `asset_packages`
  (name, version, epoch, arch, source).
- **Windows (later, remote cloud VMs):** installed updates/hotfixes + product
  versions via WMI/PowerShell over WinRM.
- Set the asset **state** honestly: `unreachable` / `auth-failed` / `scan-failed`
  on failure; ready-for-assessment on success.

## Unmanaged-asset correlation (differentiator)
- Cross-reference discovered hosts against **AD**, **DHCP leases**, and the managed
  inventory.
- Surface: **present on the network but in no inventory** → flagged unmanaged asset
  with the evidence (seen by sweep at IP X, DHCP lease Y, absent from AD/inventory).
- These are findings the customer's existing tools miss — see `docs/DIFFERENTIATORS.md`.

## Data
Extends Phase 1: `assets` (managed, source), `asset_packages`; a discovery-run record
for provenance; correlation results linking an asset to AD/DHCP evidence.

## Exit criteria
Sweep finds the lab containers on `localhost` ports; Linux package inventory populated
for all 5 distros over SSH; a synthetic "seen but not in inventory" host is correctly
flagged unmanaged; everything tenant-scoped (RLS holds); all connector calls
time-bounded and idempotent.
