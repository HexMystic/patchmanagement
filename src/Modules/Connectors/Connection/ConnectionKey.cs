using System.Text;

namespace PatchManagement.Connectors.Connection;

/// <summary>
/// Builds a stable pool key from a <see cref="ConnectionPlan"/>. Two operations share a pooled,
/// already-authenticated session only when the key matches exactly. Contains only references and
/// ids — never secret material — so it is safe to hold, compare and log.
/// </summary>
public static class ConnectionKey
{
    /// <summary>
    /// The key is <c>tenant|hop=&gt;…=&gt;destination</c>, each node being
    /// <c>host:port#credentialId@username</c>.
    ///
    /// <para><b>Tenant is first, and it is load-bearing.</b> Without it the key was
    /// <c>host:port#credentialId</c>, so two tenants targeting the same host with the same credential
    /// reference shared one authenticated transport. Isolation then rested on credential ids
    /// happening to be unique per tenant — an incidental property of the data rather than an enforced
    /// one, which a restored backup, a seeded demo tenant or a future shared-credential feature would
    /// quietly break. RLS keeps tenants apart in the database; nothing was keeping them apart in the
    /// connection pool.</para>
    ///
    /// <para><b>Username is included</b> because two bastion hops differing only by login are
    /// genuinely different connections; omitting it collided them onto one session.</para>
    /// </summary>
    public static string For(ConnectionPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var sb = new StringBuilder();
        sb.Append(plan.TenantId).Append('|');

        foreach (var hop in plan.Hops)
            Append(sb, hop).Append("=>");

        Append(sb, plan.Destination);
        return sb.ToString();
    }

    private static StringBuilder Append(StringBuilder sb, HopSpec hop) =>
        sb.Append(hop.Host)
          .Append(':').Append(hop.Port)
          .Append('#').Append(hop.Credential.Id)
          .Append('@').Append(hop.Username ?? "-");

    /// <summary>
    /// The per-host budget dimension: host and port, ignoring tenant and credential. A remote host
    /// cares how many sessions IT is serving, not who they belong to — so the cap that protects it
    /// must be shared across tenants rather than counted per tenant.
    /// </summary>
    public static string HostKeyFor(ConnectionPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        // The first hop is what a bastion-tunnelled connection actually opens a socket to; the
        // destination is reached through it, so the bastion is the host under load.
        var reached = plan.Hops.Count > 0 ? plan.Hops[0] : plan.Destination;
        return $"{reached.Host}:{reached.Port}";
    }
}
