using Npgsql;
using PatchManagement.Content.Abstractions;
using PatchManagement.Contracts.Content;

namespace PatchManagement.Content.IntegrationTests;

/// <summary>
/// A connector that returns a batch the test wrote, or throws where the test says to. It exists so
/// <c>ContentSyncService</c>'s ORCHESTRATION — transaction boundary, two-pass patch/edge ordering,
/// cursor advance-or-hold — can be exercised without a feed, a network, or a parser.
/// </summary>
internal sealed class ScriptedConnector(string kind, NormalizedBatch batch, Exception? throws = null)
    : IContentConnector
{
    /// <summary>The state the service handed over — lets a test assert the persisted cursor came back.</summary>
    public ContentSourceState? ObservedState { get; private set; }

    public string Kind { get; } = kind;

    public Task<NormalizedBatch> SyncAsync(ContentSourceState state, CancellationToken ct)
    {
        ObservedState = state;
        return throws is not null ? Task.FromException<NormalizedBatch>(throws) : Task.FromResult(batch);
    }
}

/// <summary>
/// Hands <c>ContentSyncService</c> a fresh connection on the fixture's ephemeral database. A fresh
/// one per call is required, not incidental: the service disposes the connection it is given.
/// </summary>
internal sealed class FixtureConnectionFactory(ContentPostgresFixture fx) : IContentConnectionFactory
{
    public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
    {
        var conn = new NpgsqlConnection(fx.ContentConnectionString);
        await conn.OpenAsync(ct);
        return conn;
    }
}
