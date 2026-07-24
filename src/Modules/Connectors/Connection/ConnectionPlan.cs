using PatchManagement.Connectors.Model;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Connection;

/// <summary>One node in a connection path: a host reached with a credential reference.</summary>
public sealed record HopSpec(string Host, int Port, CredentialRef Credential, string? Username);

/// <summary>
/// A fully-resolved, provider-neutral plan for reaching a target: an ordered list of
/// intermediate <see cref="Hops"/> (jump/bastion hosts, in traversal order) followed by the
/// <see cref="Destination"/>. An empty <see cref="Hops"/> list means a direct connection.
///
/// This is a pure value derived from configuration alone. There is <b>no</b> cloud-provider
/// branch anywhere in its construction (ADR 0003) — a bastion is just "a host reached first".
/// </summary>
public sealed record ConnectionPlan(HopSpec Destination, IReadOnlyList<HopSpec> Hops)
{
    public bool IsDirect => Hops.Count == 0;
}

/// <summary>
/// Builds a <see cref="ConnectionPlan"/> from an <see cref="EndpointTarget"/>. Pure and total:
/// direct when no bastion is configured, tunnelled when one is. Selecting the path is data, not a
/// code branch on where the target lives — this is the whole point of ADR 0003 and is asserted by
/// a unit test that exercises the bastion path without any cloud assumption.
/// </summary>
public static class ConnectionPlanner
{
    public static ConnectionPlan Plan(EndpointTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);

        var destination = new HopSpec(target.Host, target.EffectivePort, target.Credential, Username: null);

        if (target.Bastion is { } bastion)
        {
            var hop = new HopSpec(
                bastion.Host,
                bastion.Port > 0 ? bastion.Port : EndpointProtocolDefaults.SshPort,
                bastion.Credential,
                bastion.Username);
            return new ConnectionPlan(destination, [hop]);
        }

        return new ConnectionPlan(destination, []);
    }
}
