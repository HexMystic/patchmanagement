# 3. Cloud-agnostic endpoint connector (bastion = configuration)

- **Status:** Accepted
- **Date:** 2026-07-24

## Context
Windows test targets will be remote cloud VMs added later (no local Hyper-V). It is
tempting to encode a specific cloud's access pattern (e.g., Azure Bastion) into the
connector. That would leak provider assumptions into core code we'd later regret.

## Decision
The connector is **provider-neutral**. It speaks WinRM/SSH to an `EndpointTarget`
and never knows whether that target is on-prem, Azure, AWS, or GCP. **Direct vs
bastion/jump-host is a property of the target configuration**, not connector logic.

## Consequences
- We can add any cloud later with zero connector changes.
- Bastion/jump support is designed in from the start as a config concern.

## Rejected
- **Commit to Azure now** — provider assumptions leak into code; costly to unwind.
