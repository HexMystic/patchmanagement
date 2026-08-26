namespace PatchManagement.Contracts.Discovery;

/// <summary>
/// Sweeps IPv4 ranges for reachable hosts and open management ports.
///
/// <para>Lives in <c>PatchManagement.Contracts</c> for the same reason
/// <c>IEndpointConnector</c> (ADR 0017) and <c>IContentConnector</c> (ADR 0018) do: the host
/// composition test must be able to assert the Discovery module is reachable in the shipped app
/// <b>without referencing the module</b>. A test project that referenced it would copy the DLL into
/// its own output, discovery would find that copy, and the test would pass while the API shipped
/// without the module — the exact defect that has now landed three times in this repo.</para>
///
/// <para>Time-bounded and idempotent per CLAUDE.md NEVER #5: every probe carries an explicit budget
/// and a <see cref="CancellationToken"/>, and sweeping the same range twice observes the same hosts
/// without writing anything.</para>
/// </summary>
public interface INetworkSweeper
{
    Task<SweepResult> SweepAsync(SweepRequest request, CancellationToken ct);
}
