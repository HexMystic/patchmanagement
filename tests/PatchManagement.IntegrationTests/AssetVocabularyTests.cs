using PatchManagement.Persistence.Entities;
using Xunit;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Pins <see cref="AssetSources"/> against the live <c>ck_assets_source</c>, and — the part that is
/// not merely hygiene — pins <c>ux_assets_discovery_candidate</c>'s predicate against the same
/// constraint.
///
/// <para><b>The dependency this closes.</b> The discovery natural key
/// ([ADR 0024](../../docs/adr/0024-asset-discovery-natural-key.md)) is a PARTIAL index,
/// <c>WHERE source = 'discovery' AND ...</c>. Its correctness rests on that literal continuing to be
/// a value the column actually holds. Retire it, rename it, or typo it in a later migration and the
/// index matches no rows: the discovery upsert loses the thing it conflicts against, duplicate
/// candidates start accumulating on every sweep, and <b>nothing fails</b> — no error, no constraint
/// violation, just an idempotency guarantee that quietly stopped being one.</para>
///
/// <para>That is why the predicate is read from the catalog and cross-checked against the CHECK,
/// rather than either being compared to a C# constant. Both sides are read from what Postgres will
/// enforce.</para>
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class AssetVocabularyTests(PostgresFixture fx)
{
    private const string Constraint = "ck_assets_source";
    private const string Table = "assets";
    private const string CandidateIndex = "ux_assets_discovery_candidate";

    [Fact]
    public async Task The_source_check_accepts_exactly_the_declared_vocabulary()
    {
        var accepted = await AcceptedAsync();

        Assert.NotEmpty(accepted); // control: a constraint that parsed to nothing must not pass
        Assert.Equal(new SortedSet<string>(AssetSources.All, StringComparer.Ordinal), accepted);
    }

    /// <summary>
    /// The direction that bites at runtime: a vocabulary value the database would reject. Slice 4's
    /// correlation writes <c>ad</c>, <c>dhcp</c> and <c>inventory</c>, none of which exists in any
    /// row today — so this is the assertion that stops the constraint from being scoped to what
    /// happened to be in use when it was written.
    /// </summary>
    [Fact]
    public async Task Every_declared_source_is_a_value_the_database_will_accept()
    {
        var accepted = await AcceptedAsync();

        foreach (var source in AssetSources.All)
        {
            Assert.True(
                accepted.Contains(source),
                $"AssetSources.{source} is declared but ck_assets_source rejects it. A write would "
                + "fail with 23514. Migrate the constraint rather than relaxing this test.");
        }
    }

    /// <summary>
    /// The reverse: an accepted value nothing declares. Not a crash — a value nothing can write,
    /// which reads as dead vocabulary and invites the next person to repurpose it.
    /// </summary>
    [Fact]
    public async Task The_database_accepts_no_source_that_nothing_declares()
    {
        var accepted = await AcceptedAsync();
        var orphans = accepted.Except(AssetSources.All, StringComparer.Ordinal).ToArray();

        Assert.True(
            orphans.Length == 0,
            $"ck_assets_source accepts value(s) nothing declares: {string.Join(", ", orphans)}.");
    }

    /// <summary>
    /// The natural key's dependency, enforced rather than documented. Both sides come from the
    /// catalog: the literal is extracted from the index's own predicate, and checked against what
    /// the column is actually allowed to hold.
    /// </summary>
    [Fact]
    public async Task The_discovery_candidate_index_predicate_uses_a_source_the_check_admits()
    {
        var predicate = await CheckConstraintCatalog.IndexPredicateAsync(
            fx.OwnerConnectionString, CandidateIndex);

        Assert.False(
            string.IsNullOrWhiteSpace(predicate),
            $"{CandidateIndex} is absent or no longer partial. It is the discovery natural key "
            + "(ADR 0024); without its predicate it is not that key any more.");

        // ((source = 'discovery'::text) AND (ip IS NOT NULL) AND (endpoint_port IS NOT NULL))
        var match = System.Text.RegularExpressions.Regex.Match(
            predicate!, @"source\s*=\s*'(?<value>[^']*)'");

        Assert.True(
            match.Success,
            $"{CandidateIndex}'s predicate no longer constrains source, so it is keying more rows "
            + $"than the discovery candidates ADR 0024 scoped it to. Predicate: {predicate}");

        var literal = match.Groups["value"].Value;
        var accepted = await AcceptedAsync();

        Assert.True(
            accepted.Contains(literal),
            $"{CandidateIndex} filters on source = '{literal}', which ck_assets_source does NOT "
            + "admit. The index therefore matches no rows, the discovery upsert has nothing to "
            + "conflict against, and duplicate candidates accumulate silently on every sweep. "
            + $"Accepted values: {string.Join(", ", accepted)}");

        // And it is specifically the discovery vocabulary, not some other admitted value.
        Assert.Equal(AssetSources.Discovery, literal);
    }

    private Task<SortedSet<string>> AcceptedAsync() =>
        CheckConstraintCatalog.AcceptedLiteralsAsync(fx.OwnerConnectionString, Table, Constraint);
}
