using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Readers;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Enforces ADR 0021: <c>api/openapi.yaml</c> is the AUTHORITATIVE, hand-authored contract, and the
/// host conforms to it. Review finding H5 had two halves — the file contradicted itself about which
/// direction was authoritative, and <em>nothing read it</em>. The ADR settles the first; this class
/// is the second, and it is the whole reason the ADR can claim OpenAPI belongs on CLAUDE.md §4.5's
/// frozen list at all. A contract nothing checks is a document, not a contract.
///
/// <para>The comparison is deliberately BIDIRECTIONAL. A route missing from the spec is a stowaway
/// endpoint shipping without a contract; a spec path with no route is a promise the API does not
/// keep, and Phase 12 would build a UI against it. Bidirectionality is also what makes design-first
/// real rather than aspirational: specifying an endpoint FIRST turns this suite red until someone
/// implements it, which is this repo's red-first discipline applied to the API surface.</para>
///
/// <para>Three of the four tests here are CONTROL assertions. A convention test that silently
/// matches nothing is this project's characteristic failure — it has shipped green three times
/// (docs/ROADMAP.md, Phase 3 R4). A spec that failed to parse, or a host whose endpoints could not
/// be enumerated, would both yield two empty sets and compare EQUAL: perfect agreement, checked
/// nothing. Each is pinned below.</para>
/// </summary>
public sealed class OpenApiContractTests
{
    // -------------------------------------------------------------------------------------------
    // The contract
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The one that matters. Every implemented route+verb must appear in the spec, and every spec
    /// path+verb must be implemented.
    /// </summary>
    [Fact]
    public void Every_route_is_in_the_contract_and_every_contract_path_is_a_route()
    {
        var specified = SpecifiedOperations();
        var implemented = ImplementedOperations();

        var (specOnly, routeOnly) = Compare(specified, implemented);

        Assert.True(
            specOnly.Count == 0 && routeOnly.Count == 0,
            Explain(specOnly, routeOnly));
    }

    // -------------------------------------------------------------------------------------------
    // Controls — each guards a way this check could pass while checking nothing
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Control: the spec was found, parsed, and is valid OpenAPI. Without this, a moved file or a
    /// YAML syntax error yields an empty path set that compares equal to an empty route set — the
    /// check passes at its loudest while reading nothing.
    /// </summary>
    [Fact]
    public void The_contract_was_actually_read_and_is_valid_openapi()
    {
        var path = SpecPath();
        var document = new OpenApiStringReader().Read(File.ReadAllText(path), out var diagnostic);

        Assert.True(
            diagnostic.Errors.Count == 0,
            $"api/openapi.yaml is not valid OpenAPI: {string.Join("; ", diagnostic.Errors.Select(e => e.Message))}");

        Assert.NotEmpty(document.Paths); // guard: a spec that parsed to zero paths must not pass
        Assert.NotEmpty(SpecifiedOperations());
    }

    /// <summary>
    /// Control: the host really was built and its endpoints really were enumerated. If
    /// <c>EndpointDataSource</c> changed shape, or the host failed to compose, the route set would
    /// be empty and drift would go unnoticed in the other direction.
    /// </summary>
    [Fact]
    public void The_route_scan_actually_found_the_hosts_endpoints()
    {
        var implemented = ImplementedOperations();

        Assert.NotEmpty(implemented); // guard: zero routes means the scan failed, not that the API is empty
    }

    /// <summary>
    /// Control (the repo's pattern-audit idiom): the comparison can actually FAIL, in both
    /// directions. Run against synthetic sets so it proves the assertion's teeth without mutating a
    /// real file. A comparison that cannot report a difference passes forever and guards nothing —
    /// which is exactly how the `-ComputerName` anchor and the statement-scoped regex shipped green.
    /// </summary>
    [Fact]
    public void The_comparison_detects_drift_in_both_directions()
    {
        var baseline = new HashSet<string> { "GET /health" };

        // A path promised by the spec that no route implements.
        var (specOnly, none) = Compare([.. baseline, "GET /diag/promised"], baseline);
        Assert.Equal(["GET /diag/promised"], specOnly);
        Assert.Empty(none);

        // A route shipping with no contract entry.
        var (nothing, routeOnly) = Compare(baseline, [.. baseline, "GET /diag/stowaway"]);
        Assert.Equal(["GET /diag/stowaway"], routeOnly);
        Assert.Empty(nothing);

        // And agreement really does compare clean, so the two above are not passing by accident.
        var (a, b) = Compare(baseline, baseline);
        Assert.Empty(a);
        Assert.Empty(b);
    }

    // -------------------------------------------------------------------------------------------
    // Helpers. Each throws rather than returning empty — see the class summary.
    // -------------------------------------------------------------------------------------------

    /// <summary>Operations the CONTRACT declares, as <c>"VERB /route"</c>.</summary>
    private static HashSet<string> SpecifiedOperations()
    {
        var document = new OpenApiStringReader().Read(File.ReadAllText(SpecPath()), out _);

        return
        [
            .. from path in document.Paths
               from operation in path.Value.Operations
               select $"{operation.Key.ToString().ToUpperInvariant()} {path.Key}"
        ];
    }

    /// <summary>
    /// Operations the HOST actually serves, as <c>"VERB /route"</c>, read from the real endpoint
    /// table of a real composed host — not from a source scan, which could not see a route added by
    /// a library. No database is needed: the factory builds the app without opening a connection,
    /// the same way <see cref="HostModuleDiscoveryTests"/> does.
    /// </summary>
    private static HashSet<string> ImplementedOperations()
    {
        using var factory = new WebApplicationFactory<Program>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints;

        var operations = new HashSet<string>();

        foreach (var endpoint in endpoints.OfType<RouteEndpoint>())
        {
            var route = endpoint.RoutePattern.RawText
                ?? throw new InvalidOperationException(
                    $"A RouteEndpoint has no RawText ('{endpoint.DisplayName}'), so it cannot be "
                    + "compared against the contract. Investigate rather than skipping it.");

            var verbs = endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods
                ?? throw new InvalidOperationException(
                    $"Route '{route}' declares no HTTP method. Every endpoint in this API is mapped "
                    + "with an explicit verb; an unconstrained one would answer requests the "
                    + "contract never described.");

            foreach (var verb in verbs)
                operations.Add($"{verb.ToUpperInvariant()} {route}");
        }

        return operations;
    }

    /// <summary>Set difference, both ways. Shared so the pattern audit exercises the real logic.</summary>
    private static (IReadOnlyList<string> SpecOnly, IReadOnlyList<string> RouteOnly) Compare(
        HashSet<string> specified, HashSet<string> implemented) =>
        ([.. specified.Except(implemented).Order()], [.. implemented.Except(specified).Order()]);

    private static string Explain(IReadOnlyList<string> specOnly, IReadOnlyList<string> routeOnly)
    {
        var lines = new List<string> { "api/openapi.yaml and the host disagree (ADR 0021)." };

        if (routeOnly.Count > 0)
            lines.Add(
                "Routes the host serves that the contract does not declare — add them to the spec, "
                + $"or remove them: {string.Join(", ", routeOnly)}");

        if (specOnly.Count > 0)
            lines.Add(
                "Paths the contract promises that no route implements — implement them, or remove "
                + $"them from the spec: {string.Join(", ", specOnly)}");

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// Locates the contract by walking up to the solution file. Anchored on the repository, never on
    /// the working directory, which differs between the IDE, the CLI and a worktree. Mirrors the
    /// walk-up in <see cref="HostModuleDiscoveryTests"/>; consolidating the copies of this is a
    /// separate cleanup with no owner yet.
    /// </summary>
    private static string SpecPath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "PatchManagement.sln")))
            directory = directory.Parent;

        if (directory is null)
            throw new InvalidOperationException(
                $"Could not locate PatchManagement.sln walking up from '{AppContext.BaseDirectory}'.");

        var path = Path.Combine(directory.FullName, "api", "openapi.yaml");

        return File.Exists(path)
            ? path
            : throw new FileNotFoundException(
                "The OpenAPI contract is missing — this check would otherwise pass against nothing.", path);
    }
}
