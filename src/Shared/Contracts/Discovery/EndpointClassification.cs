using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Contracts.Discovery;

/// <summary>
/// How sure a classification is. The distinction is load-bearing rather than decorative: a sweep
/// that reported a guess with the same weight as an observation would send an operator to the wrong
/// team, and would let a connector be chosen on the strength of something nobody actually saw.
/// </summary>
public enum ClassificationConfidence
{
    /// <summary>Nothing usable was observed. The endpoint stays unclassified.</summary>
    None,

    /// <summary>Inferred from the port alone — the endpoint answered, but told us nothing.</summary>
    Port,

    /// <summary>The endpoint identified itself. Read from what it actually sent.</summary>
    Banner,
}

/// <summary>
/// What a sweep could work out about an endpoint <b>before logging in</b>: which protocol to speak,
/// and what OS family it belongs to (Phase 4 criterion (b)).
///
/// <para><b>This is deliberately shallow, and the shallowness is the honest part.</b> Classification
/// happens with no credential and no session, so it knows only what an endpoint volunteers.
/// <see cref="OsFamily"/> is <c>unknown</c> whenever nothing said otherwise — never a guess derived
/// from what the rest of the fleet happens to look like. Establishing a distro for certain requires
/// reading <c>/etc/os-release</c>, which requires a login, which is inventory.</para>
/// </summary>
public sealed record EndpointClassification
{
    /// <summary>The protocol a connector should speak to this endpoint.</summary>
    public required EndpointProtocol Protocol { get; init; }

    /// <summary>
    /// Broad family — <c>debian</c>, <c>rhel</c>, <c>windows</c> — or <c>unknown</c> when the
    /// endpoint said nothing that establishes one.
    /// </summary>
    public required string OsFamily { get; init; }

    /// <summary>
    /// The distro when it named itself (<c>ubuntu</c>, <c>debian</c>), otherwise null. Null is a
    /// normal, common answer, not a failure.
    /// </summary>
    public string? OsId { get; init; }

    public required ClassificationConfidence Confidence { get; init; }

    /// <summary>The raw text this was read from, for explainability. Never a secret.</summary>
    public string? Evidence { get; init; }

    /// <summary>The family value used when nothing observed establishes one.</summary>
    public const string UnknownFamily = "unknown";
}
