using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace PatchManagement.Persistence.Rls;

/// <summary>
/// Sets the <c>app.tenant_id</c> GUC on every DB connection open so PostgreSQL RLS scopes
/// all queries to the current tenant.
///
/// Design note: we set the GUC on EVERY connection open (session scope via <c>set_config</c>),
/// rather than <c>SET LOCAL</c> inside a transaction. This is leak-safe under connection
/// pooling BECAUSE the value is unconditionally overwritten on each open — a pooled connection
/// can never carry a previous tenant's value into a new unit of work. When no tenant is set the
/// GUC is written as empty; the RLS policy treats empty/NULL as "deny all" (fail closed).
/// </summary>
public sealed class RlsConnectionInterceptor(ITenantContext tenant) : DbConnectionInterceptor
{
    private string Value => tenant.TenantId?.ToString() ?? string.Empty;

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        Apply(connection);
        base.ConnectionOpened(connection, eventData);
    }

    public override async Task ConnectionOpenedAsync(
        DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
    {
        await ApplyAsync(connection, cancellationToken);
        await base.ConnectionOpenedAsync(connection, eventData, cancellationToken);
    }

    private void Apply(DbConnection connection)
    {
        using var cmd = CreateSetCommand(connection);
        cmd.ExecuteNonQuery();
    }

    private async Task ApplyAsync(DbConnection connection, CancellationToken ct)
    {
        await using var cmd = CreateSetCommand(connection);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private DbCommand CreateSetCommand(DbConnection connection)
    {
        var cmd = connection.CreateCommand();
        // set_config parameterizes the value safely (SET cannot take parameters).
        cmd.CommandText = "SELECT set_config('app.tenant_id', @tenant, false)";
        var p = cmd.CreateParameter();
        p.ParameterName = "tenant";
        p.Value = Value;
        cmd.Parameters.Add(p);
        return cmd;
    }
}
