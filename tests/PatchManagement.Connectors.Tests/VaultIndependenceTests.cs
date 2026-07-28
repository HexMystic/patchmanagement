using PatchManagement.Connectors.Ssh;
using PatchManagement.Connectors.Tests.Fakes;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Tests;

/// <summary>
/// phase-3.md requires the connector suite to run "without the Phase 2 vault" so Phases 2 and 3 stay
/// genuinely parallel. That is normally asserted by reading the csproj, which stops being true the
/// moment someone adds a reference for one convenient helper. This asserts it mechanically.
/// </summary>
public sealed class VaultIndependenceTests
{
    [Fact]
    public async Task No_vault_assembly_is_loaded_after_exercising_the_connector()
    {
        // Drive a real operation first: a reference that is never used loads no assembly, so
        // asserting before doing any work would pass trivially.
        var harness = ConnectorHarness.Build();
        await harness.Connector.RunAsync(
            ConnectorHarness.Target(),
            new RemoteCommand { CommandLine = "true" },
            CancellationToken.None);

        var vault = AppDomain.CurrentDomain.GetAssemblies()
            .Select(a => a.GetName().Name)
            .Where(n => n is not null && n.StartsWith("PatchManagement.Vault", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            vault.Count == 0,
            $"The connector suite loaded [{string.Join(", ", vault)}]. Phase 3 must run without the "
            + "Phase 2 vault (docs/phases/phase-3.md) — the connector depends on the ICredentialProvider "
            + "abstraction in Contracts, never on the vault implementation.");
    }

    [Fact]
    public void The_connector_assembly_does_not_reference_the_vault()
    {
        var referenced = typeof(SshConnector).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => n.StartsWith("PatchManagement.Vault", StringComparison.Ordinal))
            .ToList();

        Assert.True(referenced.Count == 0,
            $"PatchManagement.Connectors references [{string.Join(", ", referenced)}].");
    }
}
