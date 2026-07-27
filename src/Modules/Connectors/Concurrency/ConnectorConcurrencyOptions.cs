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

    /// <summary>
    /// Ceiling on simultaneous operations against any single host, summed ACROSS tenants.
    ///
    /// <para>Shared across tenants deliberately: a remote host cares how much work it is being asked
    /// to do in total, not who is asking. Without this dimension a single tenant could aim its whole
    /// per-tenant budget at one machine and flatten it while every global and per-tenant number still
    /// looked healthy.</para>
    ///
    /// <para>With SSH these are multiplexed channels on a shared transport rather than separate TCP
    /// connections, so this bounds concurrent <em>operations</em> against the host — which is the
    /// thing that actually consumes its CPU and disk.</para>
    /// </summary>
    public int PerHostMaxConnections { get; set; } = 16;

    /// <summary>Idle SSH sessions are evicted from the pool after this long.</summary>
    public TimeSpan PooledSessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

    public void Validate()
    {
        if (GlobalMaxConnections <= 0)
            throw new ArgumentOutOfRangeException(nameof(GlobalMaxConnections), GlobalMaxConnections, "Must be > 0.");
        if (PerTenantMaxConnections <= 0)
            throw new ArgumentOutOfRangeException(nameof(PerTenantMaxConnections), PerTenantMaxConnections, "Must be > 0.");
        if (PerHostMaxConnections <= 0)
            throw new ArgumentOutOfRangeException(nameof(PerHostMaxConnections), PerHostMaxConnections, "Must be > 0.");
    }
}
