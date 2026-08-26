using System.Text.RegularExpressions;
using Npgsql;
using Xunit;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Reads what the database will actually enforce, from the live catalog.
///
/// <para><b>Why the catalog and not the C# source.</b> A vocabulary test that parsed the migration
/// or the <c>AppDbContext</c> would be comparing two things this repo wrote to each other, and would
/// stay green against a database that had never had the migration applied. What matters is the
/// constraint Postgres will raise <c>23514</c> from at 3am.</para>
///
/// <para>Shared by <see cref="SweepVocabularyTests"/> and <see cref="AssetVocabularyTests"/>. Two
/// copies of this parse would fork — that is the failure this repo keeps writing tests about — and
/// the reconciliation would then need its own test.</para>
/// </summary>
internal static class CheckConstraintCatalog
{
    /// <summary>
    /// The string literals a named CHECK constraint admits.
    ///
    /// <para>Fails rather than returning an empty set when the constraint is absent. A convention
    /// test that silently matches nothing is this project's characteristic failure — it has shipped
    /// green three times — and here it would mean an unapplied migration reading as a clean pass.</para>
    /// </summary>
    public static async Task<SortedSet<string>> AcceptedLiteralsAsync(
        string ownerConnectionString, string table, string constraint)
    {
        var definition = await DefinitionAsync(ownerConnectionString, table, constraint);

        Assert.False(
            string.IsNullOrWhiteSpace(definition),
            $"{constraint} is not present on public.{table}. Either the migration has not been "
            + "applied or the constraint was renamed — both make this pin inert.");

        // CHECK ((source = ANY (ARRAY['discovery'::text, 'ad'::text, ...])))
        return [.. Regex.Matches(definition!, @"'(?<value>[^']*)'::text")
            .Select(m => m.Groups["value"].Value)];
    }

    /// <summary>Raw <c>pg_get_constraintdef</c> output, or null when the constraint is absent.</summary>
    public static async Task<string?> DefinitionAsync(
        string ownerConnectionString, string table, string constraint)
    {
        await using var conn = new NpgsqlConnection(ownerConnectionString);
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(
            """
            SELECT pg_get_constraintdef(c.oid)
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'public' AND t.relname = $1 AND c.conname = $2
            """,
            conn);

        cmd.Parameters.AddWithValue(table);
        cmd.Parameters.AddWithValue(constraint);

        return await cmd.ExecuteScalarAsync() as string;
    }

    /// <summary>
    /// The predicate of a partial index, from <c>pg_get_expr(indpred)</c>, or null when the index is
    /// absent or is not partial.
    /// </summary>
    public static async Task<string?> IndexPredicateAsync(string ownerConnectionString, string index)
    {
        await using var conn = new NpgsqlConnection(ownerConnectionString);
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(
            """
            SELECT pg_get_expr(i.indpred, i.indrelid)
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indexrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = $1
            """,
            conn);

        cmd.Parameters.AddWithValue(index);

        return await cmd.ExecuteScalarAsync() as string;
    }
}
