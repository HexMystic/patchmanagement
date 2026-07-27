using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.WinRm;

/// <summary>
/// Transport seam for WinRM: performs the actual WS-Management exchanges. Faking it makes
/// <see cref="WinRmConnector"/> fully unit-testable (double-hop surfacing, timeout mapping, honest
/// outcomes) without a Windows host — which the dev lab does not provide and the guardrail forbids.
/// The concrete <see cref="HttpWinRmClient"/> is a real HTTPS/WS-Man implementation, integration-
/// tested later against remote Windows cloud VMs (ADR 0003). Failures surface as
/// <see cref="Ssh.ConnectorConnectException"/> so the connector maps them to honest outcomes.
///
/// The <see cref="ResolvedCredential"/> is used transiently for the call only — never stored,
/// logged, or returned (NEVER #1/#2).
/// </summary>
internal interface IWinRmClient
{
    Task ProbeAsync(EndpointTarget target, ResolvedCredential credential, TimeSpan timeout, CancellationToken ct);

    Task<CommandResult> ExecuteAsync(EndpointTarget target, ResolvedCredential credential, string command, TimeSpan timeout, CancellationToken ct);

    Task<long> UploadAsync(EndpointTarget target, ResolvedCredential credential, FileTransfer file, CancellationToken ct);

    Task<long> DownloadAsync(EndpointTarget target, ResolvedCredential credential, FileTransfer file, Stream destination, CancellationToken ct);
}
