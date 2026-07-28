# ADR 0017 — The connector contract surface lives in Shared/Contracts

**Status:** Accepted — 2026-07-28 (Phase 3)
**Supersedes:** nothing. **Amends:** the implicit assumption in `phase-3.md` that
`IEndpointConnector` lives in the Connectors module.

## Context

`IEndpointConnector` and its model/result types were declared inside
`src/Modules/Connectors`, alongside the SSH.NET-backed implementation.

Two problems followed from that placement.

**The host-discovery guard could not fail honestly.** `CompositionRoot` finds modules by scanning
`PatchManagement.*.dll` in `AppContext.BaseDirectory`. Under a test host that directory is the *test
project's* output. A test project that referenced the Connectors module would put the DLL there,
discovery would succeed on that copy, and the test would pass while the shipped API still lacked the
module. That is not hypothetical: the Vault hit exactly this at `a50d9ec`, where several review
findings were latent purely because `PatchManagement.Api` never referenced `PatchManagement.Vault`.
The only way the guard can fail for the right reason is to assert through a type the test project
already has — which means a type in Contracts.

**Consumers inherited a transport.** Phase 4 (Discovery) and Phase 8 (Deployment) both consume
`IEndpointConnector`. With the interface beside SSH.NET, every consumer takes a dependency on an SSH
client it has no use for, which is precisely the coupling ADR 0003's provider-neutrality is meant to
prevent.

## Decision

`IEndpointConnector`, `EndpointTarget`, `EndpointProtocol`, `BastionHop`, `RemoteCommand`,
`FileTransfer`, `CommandResult`, `FileResult`, `ConnectivityResult`, `ConnectorOutcome`,
`EndpointFacts` and `ConnectorOutcomeMapping` live in `src/Shared/Contracts/Connectors`, namespace
`PatchManagement.Contracts.Connectors` — mirroring how `ICredentialProvider` already sits under
`Credentials/`.

Implementations stay in the module: the connectors themselves, the connection pool, the governor, the
planner, the double-hop detector and the DI registrar.

This is an **additive** change to the Phase 1 contracts, not a change to a frozen artifact. NEVER #6
enumerates the schema, RLS policies, OpenAPI, JSON schemas and the state machine; adding an interface
beside an existing one is the same class of change as `ICredentialProvider` itself.

## Consequences

- `HostModuleDiscoveryTests` asserts the Connectors module is both shipped (`deps.json`) and
  resolvable from the real host container, **without** referencing the module — so the guard retains
  the ability to fail. It did fail, red-first, before `PatchManagement.Api` gained its
  `ProjectReference`.
- A convention test (`ProviderNeutralityTests`) asserts the declaring assembly references no
  transport library, so the separation cannot erode silently.
- Phase 4 and Phase 8 consume the abstraction with no transport dependency.
- The move surfaced a genuine defect that placement had hidden: the connectors were registered as
  singletons while consuming the scoped `ICredentialProvider` — a captive dependency that .NET's
  scope validation rejects, meaning the module **could not resolve in the shipped host at all**.
  Lifetimes are now split: the process-wide connection budget stays singleton, the tenant-scoped
  composition is scoped. See `ConnectorsServiceCollectionExtensions`.

## Rejected alternatives

**Leave the interface in the module and assert discovery via `deps.json` alone.** Weaker: it proves
the DLL ships, not that the container resolves the module. The captive-dependency bug above would
have survived that check, because the assembly was present and correct — it simply could not be
constructed.

**Reference the module from the integration test project.** This is the trap the Vault documented.
It makes the guard incapable of failing.
