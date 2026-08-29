using PatchManagement.Contracts.Connectors;
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
public sealed record ConnectionPlan(Guid TenantId, HopSpec Destination, IReadOnlyList<HopSpec> Hops)
{
    public bool IsDirect => Hops.Count == 0;
}

/// <summary>
/// Builds a <see cref="ConnectionPlan"/> from an <see cref="EndpointTarget"/>. Pure: direct when no
/// bastion is configured, tunnelled through one hop for <see cref="EndpointTarget.Bastion"/>, and
/// through every hop of an <see cref="EndpointTarget.BastionChain"/> in order. Selecting the path is
/// data, not a code branch on where the target lives — this is the whole point of ADR 0003 and is
/// asserted by unit tests that exercise both bastion shapes without any cloud assumption.
///
/// <para><b>Not total.</b> It refuses a target that configures BOTH shapes, because there is no
/// correct answer to pick — see <see cref="Plan"/>. Every other target plans.</para>
/// </summary>
public static class ConnectionPlanner
{
    /// <exception cref="ArgumentException">
    /// Both <see cref="EndpointTarget.Bastion"/> and <see cref="EndpointTarget.BastionChain"/> are
    /// set. Either could plausibly be the intended topology, so choosing one by precedence would
    /// tunnel through a host the operator did not authorise and report success — the same class of
    /// failure as silently truncating a chain, one level up. Refusing is the only honest option.
    /// </exception>
    public static ConnectionPlan Plan(EndpointTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (target.Bastion is not null && target.BastionChain is not null)
        {
            throw new ArgumentException(
                "This target sets both Bastion and BastionChain. They are two spellings of one "
                + "topology and there is no safe way to choose between them: configure Bastion for a "
                + "single jump host, or BastionChain for a path of them — not both.",
                nameof(target));
        }

        var destination = new HopSpec(target.Host, target.EffectivePort, target.Credential, Username: null);

        // The shorthand is exactly a chain of one, so it is normalised into one here rather than
        // handled by a parallel branch — a second code path is how the two spellings would drift.
        IReadOnlyList<BastionHop> hops = [];
        if (target.BastionChain is { } chain)
            hops = chain.Hops;
        else if (target.Bastion is { } single)
            hops = [single];

        return new ConnectionPlan(target.TenantId, destination, [.. hops.Select(ToHopSpec)]);
    }

    private static HopSpec ToHopSpec(BastionHop hop) => new(
        hop.Host,
        hop.Port > 0 ? hop.Port : EndpointProtocolDefaults.SshPort,
        hop.Credential,
        hop.Username);
}
