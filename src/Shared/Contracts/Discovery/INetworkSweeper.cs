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
    /// <summary>
    /// Sweeps the requested ranges.
    ///
    /// <para><b>The name is deliberate — do not "tidy" it to <c>Sweep</c>-something.</b> The
    /// cross-tenant scope-factory seam ADR 0014 introduced has a method of that name, and the Phase 2
    /// convention test fencing that seam works by scanning every <c>.cs</c> file under <c>src/</c>
    /// for the bare token, <b>comments included</b>. A network sweep and a tenant sweep are
    /// unrelated, but the scan cannot tell them apart and is right not to try.</para>
    ///
    /// <para>The newcomer gives way rather than the guard. Putting this module on that test's
    /// allowlist would blind it to a genuine cross-tenant call from here later — it allows FILES,
    /// not tokens — and loosening its vocabulary would be Phase 4 weakening a Phase 2 convention to
    /// suit itself. The nouns stay <c>Sweep*</c>, because that is the domain's word and no rule
    /// objects to them.</para>
    /// </summary>
    Task<SweepResult> ScanAsync(SweepRequest request, CancellationToken ct);
}
