using System.Collections.Concurrent;
using System.Text.Json;
using Json.Schema;
using Xunit;

namespace PatchManagement.IntegrationTests;

/// <summary>Validates the sample content records against the frozen JSON schemas.</summary>
public class SchemaValidationTests
{
    // JsonSchema.FromFile registers the schema by $id in a global registry; loading the same
    // file twice throws. Cache so each schema file is loaded (and registered) exactly once.
    private static readonly ConcurrentDictionary<string, JsonSchema> SchemaCache = new();

    private static JsonSchema LoadSchema(string schemaFile) =>
        SchemaCache.GetOrAdd(schemaFile, f => JsonSchema.FromFile(Path.Combine(SchemasDir(), f)));

    [Theory]
    [InlineData("advisory.schema.json", "advisory.sample.json")]
    [InlineData("finding.schema.json", "finding.sample.json")]
    public void Sample_records_validate_against_their_schema(string schemaFile, string sampleFile)
    {
        var schema = LoadSchema(schemaFile);
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(SchemasDir(), "samples", sampleFile)));

        var result = schema.Evaluate(doc.RootElement);

        Assert.True(result.IsValid, $"{sampleFile} should validate against {schemaFile}");
    }

    [Fact]
    public void A_finding_missing_required_state_is_rejected()
    {
        var schema = LoadSchema("finding.schema.json");
        using var doc = JsonDocument.Parse("""
        {
          "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
          "tenantId": "11111111-1111-1111-1111-111111111111",
          "assetId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          "reversible": false
        }
        """);

        var result = schema.Evaluate(doc.RootElement);

        Assert.False(result.IsValid);
    }

    private static string SchemasDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "schemas");
            if (File.Exists(Path.Combine(candidate, "advisory.schema.json")))
                return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate the repo-root 'schemas' directory.");
    }
}
