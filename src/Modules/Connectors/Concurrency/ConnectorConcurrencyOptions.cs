namespace PatchManagement.Connectors.Concurrency;

/// <summary>
/// Caps for the connection governor — the scaling wall at the 10,000-endpoint target is
/// concurrent connections, not the database (CLAUDE.md §2). Bound to configuration section
/// <c>Connectors:Concurrency</c>.
/// </summary>
public sealed class ConnectorConcurrencyOptions
{
    public const string SectionName = "Connectors:Concurrency";

    /// <summary>Hard ceiling on simultaneous endpoint connections across the whole process.</summary>
    public int GlobalMaxConnections { get; set; } = 200;

    /// <summary>Ceiling on simultaneous connections for any single tenant (fairness/backpressure).</summary>
    public int PerTenantMaxConnections { get; set; } = 50;

    /// <summary>Idle SSH sessions are evicted from the pool after this long.</summary>
    public TimeSpan PooledSessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

    public void Validate()
    {
        if (GlobalMaxConnections <= 0)
            throw new ArgumentOutOfRangeException(nameof(GlobalMaxConnections), GlobalMaxConnections, "Must be > 0.");
        if (PerTenantMaxConnections <= 0)
            throw new ArgumentOutOfRangeException(nameof(PerTenantMaxConnections), PerTenantMaxConnections, "Must be > 0.");
    }
}
