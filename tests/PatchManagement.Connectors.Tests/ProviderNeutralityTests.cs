using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests;

/// <summary>
/// Exit criterion (a): the connector is provider-neutral. ADR 0003 says direct-vs-bastion is a
/// property of the target configuration, and that the connector never knows whether it is talking to
/// on-prem, Azure, AWS or GCP. These turn that into something the build can check.
/// </summary>
public sealed class ProviderNeutralityTests
{
    /// <summary>
    /// The assembly declaring <see cref="IEndpointConnector"/> must not drag in a protocol library.
    ///
    /// <para>This is the machine-checkable form of "consumers depend on the abstraction, not the
    /// implementation". Phase 4 (Discovery) and Phase 8 (Deployment) both consume this interface; if
    /// it ships in the same assembly as SSH.NET, every consumer inherits an SSH client it has no use
    /// for, and the host-module discovery guard cannot assert the module loads without referencing
    /// it — which is exactly the check that caught the Phase 2 missing-reference bug.</para>
    /// </summary>
    [Fact]
    public void Contracts_assembly_declaring_the_connector_does_not_reference_a_protocol_library()
    {
        var declaring = typeof(IEndpointConnector).Assembly;

        var offenders = declaring.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => n.Contains("SshNet", StringComparison.OrdinalIgnoreCase)
                        || n.Contains("Renci", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"'{declaring.GetName().Name}' declares IEndpointConnector but references " +
            $"[{string.Join(", ", offenders)}]. The contract surface must live in an assembly that " +
            "carries no transport dependency.");
    }
}
