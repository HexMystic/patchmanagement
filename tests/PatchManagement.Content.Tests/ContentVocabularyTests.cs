using System.Reflection;
using System.Text.Json;
using PatchManagement.Contracts.Content;
using PatchManagement.TestSupport;

namespace PatchManagement.Content.Tests;

/// <summary>
/// The content vocabulary is frozen in Phase 1 (CLAUDE.md §4.1, ADR 0010) and written down more
/// than once: as constants in <see cref="Feeds"/>/<see cref="Ecosystems"/>, as CHECK-constraint
/// arrays in <c>AppDbContext</c>, and as enums in <c>schemas/*.json</c>. Nothing tied the copies
/// together, so a divergence surfaced only as a Postgres <c>23514</c> at ingest time — after a
/// connector had been written, reviewed and merged.
///
/// <para>These pin the constants against the JSON schemas. The CHECK-constraint copy is deliberately
/// NOT covered here: collapsing it changes what a migration emits, which is a frozen-contract
/// question under NEVER #6. Recorded as a residual in ADR 0018, owner Phase 6.</para>
///
/// <para>Every case carries a control assertion that the schema was actually read and the enum
/// actually found. A convention test that silently matches nothing is this project's characteristic
/// failure — it has shipped green three times (docs/ROADMAP.md, Phase 3 R4).</para>
/// </summary>
public sealed class ContentVocabularyTests
{
    /// <summary>
    /// The eight feeds. <c>$defs/feed</c> is the WIDE list — it is what a provenance entry may cite,
    /// so it includes the overlays (kev, epss) and the patch-only catalogue (wsusscn2) that can
    /// never be an advisory's own publisher.
    /// </summary>
    [Theory]
    [InlineData("advisory.schema.json")]
    [InlineData("patch.schema.json")]
    public void Every_feed_constant_is_a_legal_provenance_source(string schemaFile)
    {
        var schema = LoadSchema(schemaFile);

        var declared = EnumAt(schema, "$defs", "feed");
        Assert.Equal(ConstantsOf(typeof(Feeds)), declared);
    }

    /// <summary>
    /// An advisory's own <c>source</c> is narrower than the feed list: KEV and EPSS assert things
    /// ABOUT a CVE and never publish one, and wsusscn2 is a patch catalogue with no advisory side.
    /// Inserting <c>source = 'kev'</c> would let one CVE exist as divergent duplicate rows.
    /// </summary>
    [Fact]
    public void Advisory_publishers_exclude_the_overlays_and_the_patch_only_catalogue()
    {
        var declared = EnumAt(LoadSchema("advisory.schema.json"), "properties", "source");

        Assert.Equal(
            // Feeds.Vendor joined 2026-08-20 (ADR 0019): a third-party application vendor
            // publishing its own advisory. Generic, never per-vendor.
            new SortedSet<string> { Feeds.Nvd, Feeds.Usn, Feeds.Rhsa, Feeds.Msrc, Feeds.Dsa, Feeds.Vendor },
            declared);

        Assert.DoesNotContain(Feeds.Kev, declared);
        Assert.DoesNotContain(Feeds.Epss, declared);
        Assert.DoesNotContain(Feeds.Wsusscn2, declared);
    }

    /// <summary>
    /// A patch's <c>source</c> excludes NVD as well as the overlays: NVD describes vulnerabilities
    /// and never ships an installable fix. wsusscn2 IS here — it is the Windows applicability
    /// engine (ADR 0008), which is the half that knows what is missing on a host.
    /// </summary>
    [Fact]
    public void Patch_publishers_exclude_nvd_and_the_overlays()
    {
        var declared = EnumAt(LoadSchema("patch.schema.json"), "properties", "source");

        Assert.Equal(
            new SortedSet<string> { Feeds.Usn, Feeds.Rhsa, Feeds.Msrc, Feeds.Wsusscn2, Feeds.Dsa, Feeds.Vendor },
            declared);

        Assert.DoesNotContain(Feeds.Nvd, declared);
        Assert.DoesNotContain(Feeds.Kev, declared);
        Assert.DoesNotContain(Feeds.Epss, declared);
    }

    /// <summary>
    /// A fourth ecosystem needs a Phase 6 comparator before it needs a row (HARD-PROBLEMS #3), so
    /// the constants and the schema must not drift apart in either direction.
    /// </summary>
    [Fact]
    public void Ecosystem_constants_match_the_advisory_schema()
    {
        var schema = LoadSchema("advisory.schema.json");

        var declared = EnumAt(schema, "properties", "affects", "items", "properties", "ecosystem");
        Assert.Equal(ConstantsOf(typeof(Ecosystems)), declared);
    }

    /// <summary>
    /// <c>unknown</c> is load-bearing: a source that states no severity is never made to fabricate
    /// one, and <c>NormalizedAdvisory.Severity</c> defaults to it (HARD-PROBLEMS #8).
    /// </summary>
    [Fact]
    public void The_advisory_severity_scale_admits_unknown()
    {
        var declared = EnumAt(LoadSchema("advisory.schema.json"), "properties", "severity");

        Assert.Contains("unknown", declared);
        Assert.Equal(
            new SortedSet<string> { "none", "low", "medium", "high", "critical", "unknown" },
            declared);

        Assert.Equal("unknown", NewAdvisory().Severity);
    }

    // -----------------------------------------------------------------------------------------
    // Helpers. Each throws — never returns empty — so a case can't pass by matching nothing.
    // -----------------------------------------------------------------------------------------

    private static JsonElement LoadSchema(string fileName)
    {
        var path = RepoPaths.Source("schemas", fileName);
        if (!File.Exists(path))
            throw new FileNotFoundException($"Content schema not found — the scan would pass on nothing.", path);

        return JsonDocument.Parse(File.ReadAllText(path)).RootElement.Clone();
    }

    /// <summary>Walks to <paramref name="path"/> and reads its <c>enum</c>, naming the miss.</summary>
    private static SortedSet<string> EnumAt(JsonElement root, params string[] path)
    {
        var current = root;
        foreach (var segment in path)
        {
            if (!current.TryGetProperty(segment, out current))
                throw new InvalidOperationException(
                    $"No '{segment}' at '{string.Join('/', path)}' in the schema. The vocabulary check "
                    + "cannot fire against a schema whose shape has moved.");
        }

        if (!current.TryGetProperty("enum", out var values))
            throw new InvalidOperationException(
                $"'{string.Join('/', path)}' declares no enum, so it constrains nothing.");

        var declared = new SortedSet<string>(
            values.EnumerateArray().Select(v => v.GetString() ?? string.Empty),
            StringComparer.Ordinal);

        if (declared.Count == 0)
            throw new InvalidOperationException($"'{string.Join('/', path)}' has an empty enum.");

        return declared;
    }

    /// <summary>Every <c>public const string</c> on a vocabulary class, by reflection so a new one counts.</summary>
    private static SortedSet<string> ConstantsOf(Type vocabulary)
    {
        var values = vocabulary
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(f => f is { IsLiteral: true, IsInitOnly: false } && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

        if (values.Count == 0)
            throw new InvalidOperationException(
                $"'{vocabulary.Name}' exposes no string constants — the comparison would be vacuous.");

        return new SortedSet<string>(values, StringComparer.Ordinal);
    }

    private static NormalizedAdvisory NewAdvisory() => new()
    {
        Source = Feeds.Nvd,
        ExternalId = "CVE-2026-0001",
        Title = "probe",
        Provenance = [new ProvenanceEntry(Feeds.Nvd, DateTimeOffset.UnixEpoch)],
    };
}
