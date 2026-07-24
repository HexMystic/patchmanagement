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
    [InlineData("patch.schema.json", "patch.sample.json")]
    public void Sample_records_validate_against_their_schema(string schemaFile, string sampleFile)
    {
        var schema = LoadSchema(schemaFile);
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(SchemasDir(), "samples", sampleFile)));

        var result = schema.Evaluate(doc.RootElement);

        Assert.True(result.IsValid, $"{sampleFile} should validate against {schemaFile}");
    }

    /// <summary>
    /// DIFFERENTIATORS #4: a risk score is only defensible if its inputs are attributable, so
    /// provenance is REQUIRED rather than optional-and-usually-absent.
    /// </summary>
    [Fact]
    public void An_advisory_without_provenance_is_rejected()
    {
        var schema = LoadSchema("advisory.schema.json");
        using var doc = JsonDocument.Parse("""
        {
          "source": "nvd",
          "externalId": "CVE-2026-1234",
          "title": "Something bad",
          "severity": "high"
        }
        """);

        var result = schema.Evaluate(doc.RootElement);

        Assert.False(result.IsValid);
    }

    /// <summary>
    /// HARD-PROBLEMS #8 applied to content: a source that does not state severity must be able to
    /// say so, rather than being forced to fabricate a value.
    /// </summary>
    [Fact]
    public void An_advisory_may_report_unknown_severity()
    {
        var schema = LoadSchema("advisory.schema.json");
        using var doc = JsonDocument.Parse("""
        {
          "source": "wsusscn2",
          "externalId": "KB5034441",
          "title": "Cumulative update",
          "severity": "unknown",
          "provenance": [
            { "source": "wsusscn2", "retrievedAt": "2026-06-11T03:40:00Z" }
          ]
        }
        """);

        var result = schema.Evaluate(doc.RootElement);

        Assert.True(result.IsValid, "severity 'unknown' must be representable");
    }

    /// <summary>
    /// The extension point that keeps the schema open where it needs to be (review H2): Phase 5
    /// can carry per-source fields without a frozen-contract change, while the known fields stay
    /// closed against typos.
    /// </summary>
    [Fact]
    public void Per_source_extras_are_allowed_inside_sourceMetadata_but_not_at_the_top_level()
    {
        var schema = LoadSchema("advisory.schema.json");

        using var extensible = JsonDocument.Parse("""
        {
          "source": "usn",
          "externalId": "USN-1234-1",
          "title": "t",
          "severity": "low",
          "provenance": [ { "source": "usn", "retrievedAt": "2026-06-01T00:00:00Z" } ],
          "sourceMetadata": { "anythingPhase5Needs": [1, 2, 3] }
        }
        """);
        Assert.True(schema.Evaluate(extensible.RootElement).IsValid);

        using var typo = JsonDocument.Parse("""
        {
          "source": "usn",
          "externalId": "USN-1234-1",
          "title": "t",
          "severity": "low",
          "provenance": [ { "source": "usn", "retrievedAt": "2026-06-01T00:00:00Z" } ],
          "serverity": "high"
        }
        """);
        Assert.False(schema.Evaluate(typo.RootElement).IsValid, "a misspelled top-level field must fail");
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
