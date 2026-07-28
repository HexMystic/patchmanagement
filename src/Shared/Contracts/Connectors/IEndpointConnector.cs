
namespace PatchManagement.Contracts.Connectors;

/// <summary>
/// One abstraction over "run work on a remote endpoint", agentless (CLAUDE.md §2). Concrete
/// implementations speak SSH (<c>SshConnector</c>) or WinRM (<c>WinRmConnector</c>). Callers never
/// branch on protocol, cloud, or whether a bastion is in the path — those are all properties of the
/// <see cref="EndpointTarget"/> (ADR 0003).
///
/// Every operation is idempotent and time-bounded (CLAUDE.md NEVER #5): each takes a
/// <see cref="CancellationToken"/>, each honours an explicit per-operation timeout, and none
/// waits unbounded. Failures are returned as honest, typed results — never thrown as flow.
/// </summary>
public interface IEndpointConnector
{
    /// <summary>The protocol this connector implements. Lets a registry dispatch by target.</summary>
    EndpointProtocol Protocol { get; }

    /// <summary>Probe reachability + authentication. Maps to unreachable/auth-failed honestly.</summary>
    Task<ConnectivityResult> TestConnectivityAsync(EndpointTarget target, CancellationToken ct);

    /// <summary>Run a bounded command. Returns a typed result modelling success and every failure.</summary>
    Task<CommandResult> RunAsync(EndpointTarget target, RemoteCommand command, CancellationToken ct);

    /// <summary>Push a file to the endpoint (SFTP for SSH). Idempotent and time-bounded.</summary>
    Task<FileResult> PushAsync(EndpointTarget target, FileTransfer file, CancellationToken ct);

    /// <summary>Pull a file from the endpoint. Idempotent and time-bounded.</summary>
    Task<FileResult> PullAsync(EndpointTarget target, FileTransfer file, CancellationToken ct);
}
