# Phase 3 — Endpoint Connector (parallel)

> One abstraction over "run work on a remote endpoint", with WinRM and SSH
> implementations. The connector is the scaling wall: at 10,000 endpoints the
> limit is concurrent connections, not the database. A fresh session can execute
> this doc standalone.

## Objective
`IEndpointConnector` + `WinRmConnector` + `SshConnector`, provider-neutral,
idempotent, time-bounded, with connection pooling and concurrency governance.

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
- **SshConnector** — key-based auth (Linux lab uses ed25519), `sudo` for privileged
  ops, SFTP for transfers. Tested against the lab fleet on `localhost:2201–2205`.
- **WinRmConnector** — WinRM/HTTPS, PowerShell Remoting; targets are the future
  remote Windows cloud VMs (cloud-agnostic). No dev target locally (no Hyper-V).

## Exit criteria
Provider-neutral connector; **credentials resolved only through the Phase-1
`ICredentialProvider`**, with a `FakeCredentialProvider` test double so the suite runs
**without the Phase 2 vault** (Phases 2 & 3 stay parallel); SSH integration tests pass
against all 5 lab containers (run a command, push/pull a file); timeouts enforced (a
test proves a hung op is cancelled); concurrency limiter caps sessions; bastion config
path exercised in a unit test without any cloud assumption in the connector code.
