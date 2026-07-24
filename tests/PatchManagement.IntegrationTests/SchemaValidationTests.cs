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

    /// <summary>
    /// JSON Schema treats <c>format</c> as an ANNOTATION by default, so every <c>date-time</c> and
    /// <c>uri</c> in our schemas would be decorative unless assertion is turned on explicitly.
    /// </summary>
    private static readonly EvaluationOptions Options = new() { RequireFormatValidation = true };

    private static EvaluationResults Evaluate(JsonSchema schema, JsonDocument doc) =>
        schema.Evaluate(doc.RootElement, Options);

    [Theory]
    [InlineData("advisory.schema.json", "advisory.sample.json")]
    [InlineData("finding.schema.json", "finding.sample.json")]
    [InlineData("patch.schema.json", "patch.sample.json")]
    public void Sample_records_validate_against_their_schema(string schemaFile, string sampleFile)
    {
        var schema = LoadSchema(schemaFile);
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(SchemasDir(), "samples", sampleFile)));

        var result = Evaluate(schema, doc);

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

        var result = Evaluate(schema, doc);

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
          "source": "msrc",
          "externalId": "CVE-2026-30001",
          "title": "Windows kernel elevation of privilege",
          "severity": "unknown",
          "provenance": [
            { "source": "msrc", "retrievedAt": "2026-06-11T03:40:00Z" },
            { "source": "wsusscn2", "retrievedAt": "2026-06-11T03:41:00Z" }
          ]
        }
        """);

        var result = Evaluate(schema, doc);

        Assert.True(result.IsValid, "severity 'unknown' must be representable");
    }

    /// <summary>
    /// KEV and EPSS enrich advisories; they do not publish them. They must stay valid as
    /// PROVENANCE, though — the sample above relies on that asymmetry.
    /// </summary>
    [Fact]
    public void A_scoring_overlay_is_not_a_valid_advisory_publisher()
    {
        var schema = LoadSchema("advisory.schema.json");
        using var doc = JsonDocument.Parse("""
        {
          "source": "kev",
          "externalId": "CVE-2026-1234",
          "title": "t",
          "severity": "high",
          "provenance": [ { "source": "kev", "retrievedAt": "2026-06-01T00:00:00Z" } ]
        }
        """);

        var result = Evaluate(schema, doc);

        Assert.False(result.IsValid, "'kev' is an overlay, not an advisory publisher");
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
        Assert.True(Evaluate(schema, extensible).IsValid);

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
        Assert.False(Evaluate(schema, typo).IsValid, "a misspelled top-level field must fail");
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

        var result = Evaluate(schema, doc);

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
