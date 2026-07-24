using Npgsql;
using PatchManagement.Content.Abstractions;

namespace PatchManagement.Content.Ingestion;

/// <summary>
/// Default <see cref="IContentConnectionFactory"/> — opens a connection from a fixed connection
/// string (the <c>patchmgmt_content</c> role). Registered with the connection string resolved from
/// configuration key <c>ConnectionStrings:Content</c>.
/// </summary>
public sealed class ContentConnectionFactory(string connectionString) : IContentConnectionFactory
{
    public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
    {
        var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync(ct);
        return conn;
    }
}
