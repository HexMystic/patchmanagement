# Phase 3 — Endpoint Connector (parallel)

> One abstraction over "run work on a remote endpoint", with WinRM and SSH
> implementations. The connector is the scaling wall: at 10,000 endpoints the
> limit is concurrent connections, not the database. A fresh session can execute
> this doc standalone.

## Objective
`IEndpointConnector` + `WinRmConnector` + `SshConnector`, provider-neutral,
idempotent, time-bounded, with connection pooling and concurrency governance.

> **As built:** `SshConnector` is verified end-to-end against the five-container lab fleet.
> **`WinRmConnector` has never run against a Windows host** and is written-and-unverified — see the
> scope section below before relying on it for anything.

## The abstraction
```csharp
public interface IEndpointConnector
{
    Task<ConnectivityResult> TestConnectivityAsync(EndpointTarget t, CancellationToken ct);
    Task<CommandResult>      RunAsync(EndpointTarget t, RemoteCommand cmd, CancellationToken ct);
    Task<FileResult>         PushAsync(EndpointTarget t, FileTransfer f, CancellationToken ct);
    Task<FileResult>         PullAsync(EndpointTarget t, FileTransfer f, CancellationToken ct);
}
```
- `EndpointTarget` carries host, protocol, port, a **credential reference** (an id/
  scope — never a raw secret), and an **optional bastion/jump config**.
- **Bastion is configuration, not code** (ADR 0003): the connector never knows it
  is talking to a cloud VM. Direct vs jump-host is a property of the target.

## Credentials — depend on the Phase 1 interface, NOT the Phase 2 vault
The connector resolves credentials through **`ICredentialProvider`**, an interface
**defined in the Phase 1 contracts** — it does **not** depend on the Phase 2 vault
*implementation*. This keeps **Phases 2 and 3 genuinely parallel**: neither blocks the
other.

```csharp
// Phase 1 contract (src/Shared/Contracts) — the connector only sees this.
public interface ICredentialProvider
{
    // Returns a resolved, in-memory-only credential for a reference; never logged,
    // never persisted by the connector. The real implementation is the Phase 2 vault.
    Task<ResolvedCredential> ResolveAsync(CredentialRef reference, CancellationToken ct);
}
```

- **Production wiring:** DI binds `ICredentialProvider` → the Phase 2 vault. The
  connector code is unaware of envelope encryption, key providers, or the vault at all.
- **Phase 3 integration tests:** use a **test double** (`FakeCredentialProvider`) that
  returns the lab ed25519 key material for `localhost:2201–2205`. This lets the full
  SSH connector suite run against the lab **without the Phase 2 vault existing yet**.
- The connector still honors the credential invariants (CLAUDE.md NEVER #1/#2): a
  `ResolvedCredential` is used in memory only and never logged or returned.

## Non-negotiables (CLAUDE.md NEVER #5)
- **Idempotent:** every operation is safe to retry; callers may re-invoke after a
  timeout without side-effect duplication.
- **Time-bounded:** every call takes a `CancellationToken` and an explicit timeout;
  no unbounded remote wait ever.
- **Honest results:** connectivity failures map to the state machine
  (`unreachable`, `auth-failed`) — never swallowed.

## Concurrency (the scaling wall)
- A global + per-tenant concurrency limiter (bounded connection pool, backpressure
  via Redis-backed tokens). Reuse sessions where the protocol allows; cap simultaneous
  WinRM/SSH sessions; queue the rest. Instrument connection counts.
- **Double-hop awareness:** a WinRM/PS-Remoting session cannot authenticate onward
  (e.g., to an SMB share) without CredSSP/Kerberos delegation. The connector surfaces
  this rather than hanging — see `docs/HARD-PROBLEMS.md`.

## Implementations

- **SshConnector — Linux, verified.** Key-based auth (ed25519), `sudo` for privileged ops, SFTP for
  transfers. Exercised end-to-end against all five lab containers on `localhost:2201–2205`.

- **WinRmConnector — WINDOWS, WRITTEN AND UNVERIFIED.** See below. It has never run against a
  Windows host.

## ⚠ Scope: the Windows path is written and unverified

**`WinRmConnector` and `HttpWinRmClient` have never touched a real Windows machine.** No Windows
target exists in this environment, and the lab-only guardrail denies every WinRM cmdlet from a dev
session unconditionally (ADR 0007, CLAUDE.md NEVER #4). There is no configuration of this repository
in which the Windows path can be integration-tested today.

**What the WinRM tests do prove.** `HttpWinRmClientTests` runs the client against a *scripted HTTP
handler*. It shows the client sends the exchanges it should and reacts correctly to what it is told:
credentials always reach the handler, the receive loop is bounded by its budget, remote paths cannot
break out of a PowerShell literal, and the connectivity probe performs an authenticated exchange
rather than an anonymous `Identify`. Four transport defects were found and fixed this way, each
mutation-checked.

**What they do not prove.** That a real WinRM server accepts these SOAP envelopes; that Negotiate/NTLM
negotiates as expected; that the shell lifecycle behaves as scripted; that the base64 upload/download
round-trips against real PowerShell; that double-hop detection matches how a real host fails. A green
WinRM suite is a statement about **this client**, not about **WinRM**.

**Do not read a green suite as readiness.** Real-host verification is deferred as **D-303**, owner
**Phase 8**, and the double-hop *solution* (CredSSP / constrained Kerberos) as **D-304**, also Phase 8.
Phase 3's obligation for double-hop is only to **surface** the requirement rather than hang, which it
does. Anyone planning a Windows wave should treat this connector as unproven code that compiles and
has unit coverage — not as a tested transport.

## Exit criteria — status

Every criterion below names the test that proves it. A criterion with no test named is not met,
whatever the prose says.

| # | Criterion | Proven by |
|---|-----------|-----------|
| **(a)** | Provider-neutral connector | `ProviderNeutralityTests.Contracts_assembly_declaring_the_connector_does_not_reference_a_protocol_library` · `.The_registry_resolves_a_different_connector_per_protocol` · `.An_unregistered_protocol_is_refused_by_name_rather_than_defaulted` · `.No_cloud_provider_vocabulary_appears_in_the_connector_or_its_contracts` |
| **(b)** | Credentials only via the Phase-1 `ICredentialProvider`, with a `FakeCredentialProvider` so the suite runs without the Phase 2 vault | `CredentialLifecycleTests` (5 facts: zeroing on success, auth failure and cancellation; resolution through the provider; lease release on failure) · `FakeCredentialProviderTests` (5) · `SudoTests` (5) · `VaultIndependenceTests.No_vault_assembly_is_loaded_after_exercising_the_connector` · `.The_connector_assembly_does_not_reference_the_vault` |
| **(c)** | SSH integration against **all five** lab containers — run a command, push and pull a file | `SshFleetTests`, a `[Theory]` over `LabFleet.All` (5 hosts × 8 facts) in **`PatchManagement.Connectors.IntegrationTests`**: `Connectivity_succeeds` · `A_command_runs_and_returns_its_output` · `A_file_round_trips_byte_for_byte` (64 KiB, SHA-256) · `Pushing_the_same_payload_twice_is_safe` · `A_non_zero_exit_is_reported_honestly_rather_than_thrown` · `An_elevated_command_runs_as_root` · `The_endpoint_identifies_itself_as_the_expected_distribution` · `A_wrong_key_maps_to_auth_failed_not_unreachable`. **These run against real sshd; no unit stand-in satisfies this criterion.** `LabFleetManifestTests` pins the fleet table against `lab/docker-compose.yml` and `scripts/verify-env.ps1` |
| **(d)** | Timeouts enforced; a test proves a hung op is cancelled | `TimeoutTests` (6 facts, all driven by `FakeTimeProvider` — nothing sleeps): command timeout → `Outcome.Timeout`; lease released on timeout; caller cancellation stays `OperationCanceledException` and is **not** collapsed into a timeout; transfer timeout; configurable probe budget; plus a control proving an in-budget command is untouched by the clock |
| **(e)** | Concurrency limiter caps sessions | `SessionCapTests.The_connector_never_opens_more_concurrent_sessions_than_the_global_budget` (12 concurrent ops against a budget of 3, asserted on a high-water mark) · `ConnectionGovernorTests` (8 facts: global cap, per-tenant independence, per-host cap shared across tenants, `TryAcquire` refusal, cancelled-waiter accounting, slot pruning, double-dispose) |
| **(f)** | Bastion config path in a unit test, no cloud assumption in connector code | `BastionPlanningTests` (5 facts: direct vs single-hop plan, hop ordering, per-hop credential resolved separately, multi-hop rejected by name) · `ProviderNeutralityTests.No_cloud_provider_vocabulary_appears_in_the_connector_or_its_contracts` |

**NeverLog residual (ADR 0012's hand-off to this phase):** `ConnectorLoggingConventionTests` (6) ·
`ConnectorNeverLogTests` (5, including the live-sink control) · `RemoteOutputContainmentTests` (4).
Each scan is mutation-checked — see the commit bodies for the recorded red values.

**Counts at close:** Contracts 19 · Connectors unit 86 · IntegrationTests 38 · Vault 80 (unregressed)
· **Connectors.IntegrationTests 44, zero skipped**. 267 passing, 0 skipped.

Criterion (f) does **not** claim the `ForwardedPortLocal` binding is exercised — that needs a live SSH
client and belongs to the lab suite. What is unit-proven is planning, hop ordering, per-hop credential
separation and chain rejection.
