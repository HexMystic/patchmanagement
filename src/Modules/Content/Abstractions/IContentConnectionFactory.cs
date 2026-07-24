using Npgsql;

namespace PatchManagement.Content.Abstractions;

/// <summary>
/// Opens connections as the <c>patchmgmt_content</c> role — the ONLY role that may write the global
/// catalogue (SELECT/INSERT/UPDATE, no DELETE; ADR 0010). Kept separate from the request-path
/// <c>patchmgmt_app</c> connection precisely so a request-path bug can never rewrite content for
/// every tenant at once. The connection string is a location + role, never a place credentials for
/// managed endpoints live (CLAUDE.md NEVER #1).
/// </summary>
public interface IContentConnectionFactory
{
    Task<NpgsqlConnection> OpenAsync(CancellationToken ct);
}
