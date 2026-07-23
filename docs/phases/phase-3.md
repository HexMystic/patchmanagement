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
- `EndpointTarget` carries host, protocol, port, credential-ref (resolved via the
  vault at call time — never a raw secret), and an **optional bastion/jump config**.
- **Bastion is configuration, not code** (ADR 0003): the connector never knows it
  is talking to a cloud VM. Direct vs jump-host is a property of the target.

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
Provider-neutral connector; SSH integration tests pass against all 5 lab containers
(run a command, push/pull a file); timeouts enforced (a test proves a hung op is
cancelled); concurrency limiter caps sessions; bastion config path exercised in a
unit test without any cloud assumption in the connector code.
