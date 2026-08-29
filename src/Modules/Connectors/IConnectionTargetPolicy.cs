namespace PatchManagement.Connectors;

/// <summary>
/// Decides whether the connector may contact an address at all — the in-product half of CLAUDE.md
/// NEVER #4, applied to <b>connections</b> rather than only to sweeps.
///
/// <para><b>Why this exists on top of the sweep's guard.</b> Before bastion chains, an
/// <c>EndpointTarget</c> named one address and the connector dialled it directly, so "is this
/// reachable from a dev machine" did rough duty as a scope check. D-306 removed that: a chain reaches
/// its destination from inside the network, via whichever jump host precedes it, so an out-of-lab
/// address becomes reachable <em>through</em> a lab container. Meanwhile the guard written for this
/// rule (<c>DiscoveryTargetPolicy</c>) was consumed only by the sweep, and
/// <c>.claude/hooks/lab_only_guard.py</c> inspects Bash command strings — it structurally cannot see
/// a socket opened by our own C#. So a dev session could reach an arbitrary host and nothing would
/// object.</para>
///
/// <para><b>The port is declared here and implemented over the sweep's allowlist</b>
/// (<c>Discovery:Security:AllowedTargets</c>), deliberately: a second connector-only list would be
/// two declarations of one promise, and duplication that nothing checks silently forks. It also keeps
/// this module free of any dependency on Discovery, which the layering requires.</para>
///
/// <para><b>Unregistered means unrestricted, and that is not a loophole left open by accident.</b>
/// A deployment composing the Connectors module alone has declared no scope, and inventing one for
/// it would refuse every connection in a product whose entire job is connecting. General
/// connector-target governance in production is a separate, named concern; what this closes is the
/// dev-session hole, in the environment where NEVER #4 applies and where the scope is declared.</para>
/// </summary>
public interface IConnectionTargetPolicy
{
    /// <summary>
    /// <c>null</c> when <paramref name="host"/> may be contacted, otherwise a caller-safe reason it
    /// may not.
    ///
    /// <para>Asynchronous because deciding honestly requires knowing the ADDRESS, and a host may be
    /// a name. Resolving it is the only way to tell whether it lands inside the declared scope —
    /// a policy that compared strings would be satisfied by any name that happened not to look like
    /// an out-of-scope IP.</para>
    /// </summary>
    Task<string?> RefusalReasonAsync(string host, CancellationToken ct);
}
