namespace PatchManagement.Contracts.Connectors;

/// <summary>
/// An ordered path of jump hosts to the target: <c>Hops[0]</c> is the host a socket is opened to,
/// each later hop is reached <b>through</b> the one before it, and the destination is reached
/// through the last.
///
/// <para><b>Additive, by decision (2026-08-27), not a widening of <see cref="EndpointTarget.Bastion"/>.</b>
/// The one-hop shorthand stays exactly as it was, so no existing caller or stored configuration
/// changes shape; this type is what makes the two-or-more case expressible at all. ADR 0017's
/// contract surface is extended, not altered. Before it existed, <c>ConnectionPlanner.Plan</c> could
/// only ever emit 0 or 1 hops, which left the connector's multi-hop refusal unreachable from any real
/// target — a safeguard that no configuration could trigger (D-306).</para>
///
/// <para>Provider-neutral like <see cref="BastionHop"/> itself (ADR 0003): nothing here knows or cares
/// whether a hop is an Azure Bastion, an SSM proxy or a jump box under a desk. A chain is just "these
/// hosts, in this order, each reached from the one before".</para>
/// </summary>
public sealed record BastionChain
{
    public BastionChain(IReadOnlyList<BastionHop> hops)
    {
        ArgumentNullException.ThrowIfNull(hops);

        // An empty chain would plan a DIRECT connection, silently discarding the operator's decision
        // to place this target behind a bastion. On a segmented network that either fails
        // confusingly or — worse — succeeds by a route that was supposed to be closed. There is no
        // reading of "a chain of no hops" that is safer than refusing it.
        if (hops.Count == 0)
        {
            throw new ArgumentException(
                "A BastionChain must contain at least one hop; use a null Bastion/BastionChain for a "
                + "direct connection rather than an empty chain.",
                nameof(hops));
        }

        if (hops.Any(hop => hop is null))
            throw new ArgumentException("A BastionChain cannot contain a null hop.", nameof(hops));

        Hops = [.. hops];
    }

    /// <summary>The hops in traversal order. Never empty.</summary>
    public IReadOnlyList<BastionHop> Hops { get; }

    /// <summary>Value equality over the hops, so two chains configured alike compare equal.</summary>
    public bool Equals(BastionChain? other) =>
        other is not null && Hops.SequenceEqual(other.Hops);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var hop in Hops) hash.Add(hop);
        return hash.ToHashCode();
    }
}
