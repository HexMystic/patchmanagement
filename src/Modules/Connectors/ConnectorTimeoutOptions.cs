namespace PatchManagement.Connectors;

/// <summary>
/// Time budgets the caller does not supply. Bound to configuration section
/// <c>Connectors:Timeouts</c>.
///
/// <para>Commands and transfers carry their own timeouts, because only the caller knows whether it
/// is running <c>id -u</c> or a distribution upgrade. Reaching and authenticating a host has no such
/// payload, so those budgets live here.</para>
///
/// <para><b>Why reachability and authentication are budgeted separately.</b> They were one number,
/// and that number decided the OUTCOME rather than just the deadline. Measured against the dev lab,
/// sshd takes ~10.15s to reject an unauthorised key — reproducibly, with the stock OpenSSH client,
/// so it is the server's behaviour and not the client's. Under a single 15s budget the connector ran
/// out of time mid-exchange and reported <c>Timeout</c> for what was actually a rejected credential.
/// On a real estate that gap is wider still: PAM fail-delays, fail2ban and directory-backed auth can
/// take far longer.</para>
///
/// <para>Merging them forces the fast phase to inherit the slow phase's tolerance. Reaching a host
/// either completes in a moment or the host is not reachable, so a SHORT budget there is more
/// accurate and much faster across an estate — at 10,000 endpoints a sweep over a dead subnet costs
/// hosts × timeout of held connection budget, and connection budget is the scaling wall (CLAUDE.md
/// §2). Authentication is where variable, server-controlled delay lives, so it gets room.</para>
///
/// <para>Splitting them improves both properties at once: unreachable is detected sooner, and a
/// rejected credential is finally classified as <c>auth-failed</c> rather than as a timeout — the
/// distinction that decides whether an operator calls the network team or the identity team.</para>
/// </summary>
public sealed class ConnectorTimeoutOptions
{
    public const string SectionName = "Connectors:Timeouts";

    /// <summary>
    /// Budget for establishing a TCP connection to the endpoint. Exceeding it means
    /// <c>Unreachable</c> — nothing is listening, or the network is not carrying us there.
    /// </summary>
    public TimeSpan Reachability { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Budget for the SSH transport handshake and authentication, once the host has answered.
    /// Generous on purpose: this is the phase whose duration the far end controls, and cutting it
    /// short destroys the evidence needed to tell a rejection from a hang.
    /// </summary>
    public TimeSpan Authentication { get; set; } = TimeSpan.FromSeconds(45);

    /// <summary>The whole probe: reach the host, then authenticate.</summary>
    public TimeSpan ProbeBudget => Reachability + Authentication;

    public void Validate()
    {
        if (Reachability <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(Reachability), Reachability,
                "Every remote operation must be time-bounded (CLAUDE.md NEVER #5).");
        }

        if (Authentication <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(Authentication), Authentication,
                "Every remote operation must be time-bounded (CLAUDE.md NEVER #5).");
        }
    }
}
