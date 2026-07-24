using System.Text;

namespace PatchManagement.Connectors.Connection;

/// <summary>
/// Builds a stable pool key from a <see cref="ConnectionPlan"/>. Two targets share a pooled session
/// only when host, port, credential and the full hop chain match. Contains only references/ids —
/// never secret material — so it is safe to hold and log.
/// </summary>
public static class ConnectionKey
{
    public static string For(ConnectionPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var sb = new StringBuilder();
        foreach (var hop in plan.Hops)
            Append(sb, hop).Append("=>");
        Append(sb, plan.Destination);
        return sb.ToString();
    }

    private static StringBuilder Append(StringBuilder sb, HopSpec hop) =>
        sb.Append(hop.Host).Append(':').Append(hop.Port).Append('#').Append(hop.Credential.Id);
}
