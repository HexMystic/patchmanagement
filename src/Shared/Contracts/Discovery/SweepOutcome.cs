namespace PatchManagement.Contracts.Discovery;

/// <summary>
/// The honest outcome of a network sweep. A sweep that was <b>not permitted to run</b> is not the
/// same event as a sweep that ran and found nothing, and collapsing the two is the defect this
/// enum exists to prevent — Phase 5's <c>rhsa</c> connector returned an empty batch with a green
/// status and an advanced cursor, and nothing downstream could tell that from a quiet feed.
///
/// <para>The sweep is the first feature in this product that can, by design, contact an arbitrary
/// address, so "refused" has to be louder than "empty" here more than anywhere else.</para>
/// </summary>
public enum SweepOutcome
{
    /// <summary>Every requested range was permitted and probed; the host list is trustworthy.</summary>
    Ok,

    /// <summary>
    /// At least one requested range fell outside the configured target policy. <b>Nothing was
    /// probed</b> — not even the permitted ranges (see <c>DiscoveryTargetPolicy</c> for why the
    /// refusal is all-or-nothing rather than a partial sweep).
    /// </summary>
    RefusedByPolicy,

    /// <summary>
    /// At least one requested range could not be interpreted as a bounded IPv4 CIDR block — it was
    /// malformed, it was IPv6, or it was larger than the configured per-range host cap. Nothing was
    /// probed. Refused <b>by name</b>: the offending range is named in the result rather than
    /// silently skipped.
    /// </summary>
    InvalidRange,
}
