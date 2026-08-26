using Microsoft.Extensions.Logging;

namespace PatchManagement.Discovery.Sweep;

/// <summary>
/// Decides whether a requested range is inside the scope this deployment declared — the in-product
/// half of CLAUDE.md NEVER #4 (see <see cref="DiscoverySecurityOptions"/> for why it has to exist
/// in the product rather than in a hook).
///
/// <para><b>Fail closed at every step.</b> An empty allowlist permits nothing. An allowlist entry
/// that cannot be parsed is discarded rather than widened into something permissive, so a typo
/// narrows the policy and never opens it. And a request is permitted only when a single allowed
/// block contains it <i>entirely</i> — never by stitching coverage together from several entries,
/// which is a rule worth stating because the union case is where a subtle widening would hide.</para>
/// </summary>
internal sealed class DiscoveryTargetPolicy
{
    private readonly IReadOnlyList<CidrBlock> _allowed;

    public DiscoveryTargetPolicy(DiscoverySecurityOptions options, ILogger logger)
    {
        var allowed = new List<CidrBlock>();

        foreach (var entry in options.AllowedTargets)
        {
            // long.MaxValue, not the sweep's per-range cap: an allowlist entry declares SCOPE and is
            // never enumerated, so a /8 here is a legitimate statement about an estate even though
            // sweeping a /8 in one request is not. The two bounds answer different questions.
            if (CidrBlock.TryParse(entry, long.MaxValue, out var block, out var reason))
            {
                allowed.Add(block);
            }
            else
            {
                logger.LogError(
                    "Discovery allowlist entry {Entry} is not a valid CIDR block and has been "
                    + "DISCARDED, narrowing the sweepable scope: {Reason}",
                    entry, reason);
            }
        }

        _allowed = allowed;
    }

    /// <summary>
    /// True when some single allowed block fully contains <paramref name="requested"/>.
    ///
    /// <para>Partial overlap is <b>not</b> permission. An operator who asked for a <c>/16</c> and
    /// received a sweep of the one <c>/24</c> of it that was in scope would be told what a
    /// sixty-fourth of their estate contains, with nothing in the result to distinguish that from
    /// the whole answer — so the range is refused and the operator narrows it deliberately.</para>
    /// </summary>
    public bool Permits(CidrBlock requested) => _allowed.Any(a => a.Contains(requested));

    /// <summary>Why a refusal happened, in caller-safe text that names no secret.</summary>
    public string RefusalReason(CidrBlock requested) =>
        _allowed.Count == 0
            ? "No sweepable ranges are configured. Discovery:Security:AllowedTargets is empty, which "
                + "permits nothing by design - declare the ranges this deployment may sweep."
            : $"Range {requested.Text} is not fully contained by any configured entry in "
                + "Discovery:Security:AllowedTargets. Partial overlap is refused rather than clipped.";
}
