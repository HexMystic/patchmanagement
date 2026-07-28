using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.Tests;

/// <summary>
/// ADR 0018 split the content surface in two: the connector interface and the normalized model went
/// to <c>PatchManagement.Contracts</c>; the Npgsql-shaped seams (<c>IContentStore</c>,
/// <c>IContentConnectionFactory</c>) stayed in the module. These assert the split mechanically,
/// because the pressure to erode it is real — the easiest way to make a future assessment query
/// compile is to move one more type inward.
///
/// <para>The consequence if it erodes: Contracts is referenced by every module and by
/// <c>PatchManagement.IntegrationTests</c>, so a database driver reaching it means Phase 6 and
/// Phase 7 inherit Npgsql to read a CVSS score — the coupling ADR 0017 established this pattern to
/// prevent.</para>
/// </summary>
public sealed class ContentContractSurfaceTests
{
    /// <summary>
    /// The assembly declaring <see cref="IContentConnector"/> must not drag in a database driver.
    /// The Content analogue of <c>ProviderNeutralityTests</c>'s transport check.
    /// </summary>
    [Fact]
    public void Contracts_assembly_declaring_the_content_connector_references_no_database_driver()
    {
        var declaring = typeof(IContentConnector).Assembly;

        var offenders = declaring.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => n.Contains("Npgsql", StringComparison.OrdinalIgnoreCase)
                        || n.Contains("EntityFrameworkCore", StringComparison.OrdinalIgnoreCase)
                        || n.Contains("System.Data.SqlClient", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"'{declaring.GetName().Name}' declares IContentConnector but references "
            + $"[{string.Join(", ", offenders)}]. The content contract surface must live in an "
            + "assembly that carries no database dependency (ADR 0018) — otherwise Phase 6 and "
            + "Phase 7 inherit a driver to read normalized content.");
    }

    /// <summary>
    /// The other half of the split, and the one that would silently undo the guard: the store's
    /// Npgsql-carrying seams must stay OUT of Contracts. Asserted by name, because asserting the
    /// type is in the module would pass trivially if a copy also existed in Contracts.
    /// </summary>
    [Fact]
    public void The_npgsql_carrying_seams_stay_in_the_module()
    {
        var contracts = typeof(IContentConnector).Assembly;

        var leaked = contracts.GetTypes()
            .Where(t => t.Name is "IContentStore" or "IContentConnectionFactory")
            .Select(t => t.FullName ?? t.Name)
            .ToList();

        Assert.True(
            leaked.Count == 0,
            $"[{string.Join(", ", leaked)}] moved into Contracts. Both carry NpgsqlConnection / "
            + "NpgsqlTransaction in their signatures, so promoting them puts a database driver in "
            + "the assembly every module references (ADR 0018).");
    }

    /// <summary>
    /// The move must not have left a second copy behind. Two <c>IContentConnector</c>s — one in
    /// Contracts, one in the module — would compile, and the host-discovery guard would resolve the
    /// Contracts one while connectors registered against the module one, so it would report an
    /// empty set for a module that had loaded perfectly.
    /// </summary>
    [Fact]
    public void The_module_does_not_redeclare_the_promoted_contract_types()
    {
        var promoted = new[]
        {
            "IContentConnector", "ContentSourceState", "NormalizedBatch", "NormalizedAdvisory",
            "NormalizedPatch", "NormalizedAffect", "ProvenanceEntry", "KevOverlay", "EpssOverlay",
            "Feeds", "Ecosystems",
        };

        var module = typeof(ContentModule).Assembly;

        var duplicates = module.GetTypes()
            .Where(t => promoted.Contains(t.Name, StringComparer.Ordinal))
            .Select(t => t.FullName ?? t.Name)
            .ToList();

        Assert.True(
            duplicates.Count == 0,
            $"'{module.GetName().Name}' still declares [{string.Join(", ", duplicates)}], which "
            + "ADR 0018 moved to Contracts. A shadow copy compiles and then makes the host-discovery "
            + "guard resolve a different interface from the one the connectors registered against.");
    }
}
