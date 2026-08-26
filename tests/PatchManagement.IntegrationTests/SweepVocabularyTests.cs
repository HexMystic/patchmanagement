using System.Text.RegularExpressions;
using Npgsql;
using PatchManagement.Contracts.Discovery;
using Xunit;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Pins <see cref="SweepOutcome"/> against the live <c>ck_discovery_runs_outcome</c> CHECK
/// constraint, so the C# vocabulary and the database's copy of it cannot drift apart.
///
/// <para><b>Why this exists at all.</b> The same vocabulary is now written down twice — as an enum
/// in <c>PatchManagement.Contracts</c> and as a CHECK array in <c>AppDbContext</c>. Phase 5 had
/// exactly this shape and nothing tying the copies together, and the divergence surfaced as a
/// Postgres <c>23514</c> at ingest time, after a connector had been written, reviewed and merged
/// (see <c>ContentVocabularyTests</c>).</para>
///
/// <para><b>Why this can do what ContentVocabularyTests deliberately would not.</b> That suite pins
/// the constants against the JSON schemas but leaves the CHECK-constraint copy alone, because
/// collapsing it after the fact would change what an existing migration emits — a frozen-contract
/// question under NEVER #6, recorded as an ADR 0018 residual owned by Phase 6. Here both sides were
/// authored in the same slice, so pinning them together costs nothing and closes the gap before it
/// can open.</para>
///
/// <para>The constraint is read from the live catalog with <c>pg_get_constraintdef</c> rather than
/// from the migration source. A test that read the C# would be comparing two things this repo wrote
/// to each other; what matters is what Postgres will actually enforce at 3am.</para>
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class SweepVocabularyTests(PostgresFixture fx)
{
    /// <summary>
    /// Values the database accepts that are deliberately NOT <see cref="SweepOutcome"/> members.
    ///
    /// <para><c>running</c> is a run that has not finished — a sweep in flight has no outcome, and
    /// modelling one would force the enum to carry a value the sweeper can never return.
    /// <c>failed</c> covers a run abandoned outside the sweeper, which returns a typed result for
    /// every outcome it models and therefore cannot report this one itself.</para>
    /// </summary>
    private static readonly string[] NotSweepOutcomes = ["running", "failed"];

    [Fact]
    public async Task The_outcome_check_constraint_accepts_exactly_the_sweep_outcomes_plus_the_two_run_only_states()
    {
        var accepted = await AcceptedOutcomesAsync();

        Assert.NotEmpty(accepted); // control: a constraint that parsed to nothing must not pass

        var fromEnum = Enum.GetValues<SweepOutcome>().Select(ToWireName);
        var expected = new SortedSet<string>(fromEnum.Concat(NotSweepOutcomes), StringComparer.Ordinal);

        Assert.Equal(expected, accepted);
    }

    /// <summary>
    /// The direction that actually bites: a new <see cref="SweepOutcome"/> member that the database
    /// would reject. The sweeper would return it, the store would try to persist it, and Postgres
    /// would raise 23514 at the moment a real sweep finished.
    /// </summary>
    [Fact]
    public async Task Every_sweep_outcome_is_a_value_the_database_will_accept()
    {
        var accepted = await AcceptedOutcomesAsync();

        foreach (var outcome in Enum.GetValues<SweepOutcome>())
        {
            var wire = ToWireName(outcome);
            Assert.True(
                accepted.Contains(wire),
                $"SweepOutcome.{outcome} serialises to '{wire}', which ck_discovery_runs_outcome "
                + "does not accept. A sweep returning it would fail with 23514 on persist. Add it "
                + "to DiscoveryRunOutcomes and migrate, rather than relaxing this test.");
        }
    }

    /// <summary>
    /// The reverse direction, and the reason it is a separate test: an orphan accepted value is not
    /// a crash, it is a value nothing can ever write — which reads as dead vocabulary to the next
    /// person and invites them to start using it for something else.
    /// </summary>
    [Fact]
    public async Task The_database_accepts_no_outcome_that_nothing_can_produce()
    {
        var accepted = await AcceptedOutcomesAsync();
        var producible = new SortedSet<string>(
            Enum.GetValues<SweepOutcome>().Select(ToWireName).Concat(NotSweepOutcomes),
            StringComparer.Ordinal);

        var orphans = accepted.Except(producible).ToArray();

        Assert.True(
            orphans.Length == 0,
            "ck_discovery_runs_outcome accepts value(s) that neither SweepOutcome nor a run-only "
            + $"state can produce: {string.Join(", ", orphans)}.");
    }

    /// <summary>
    /// Kebab-case, matching <c>EndpointStateNames</c>' convention for stored wire values:
    /// <c>RefusedByPolicy</c> becomes <c>refused-by-policy</c>.
    /// </summary>
    private static string ToWireName(SweepOutcome outcome) =>
        Regex.Replace(outcome.ToString(), "(?<!^)([A-Z])", "-$1").ToLowerInvariant();

    /// <summary>
    /// The literals <c>ck_discovery_runs_outcome</c> actually admits, read from the live catalog.
    /// </summary>
    private async Task<SortedSet<string>> AcceptedOutcomesAsync()
    {
        await using var conn = new NpgsqlConnection(fx.OwnerConnectionString);
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(
            """
            SELECT pg_get_constraintdef(c.oid)
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'public'
              AND t.relname = 'discovery_runs'
              AND c.conname = 'ck_discovery_runs_outcome'
            """,
            conn);

        var definition = await cmd.ExecuteScalarAsync() as string;

        Assert.False(
            string.IsNullOrWhiteSpace(definition),
            "ck_discovery_runs_outcome is not present on public.discovery_runs. Either the migration "
            + "has not been applied, or the constraint was renamed — both make this pin inert.");

        // CHECK ((outcome = ANY (ARRAY['running'::text, 'ok'::text, ...])))
        var literals = Regex.Matches(definition!, @"'(?<value>[^']*)'::text")
            .Select(m => m.Groups["value"].Value);

        return new SortedSet<string>(literals, StringComparer.Ordinal);
    }
}
