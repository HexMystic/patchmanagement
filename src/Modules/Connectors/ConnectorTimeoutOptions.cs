namespace PatchManagement.Connectors;

/// <summary>
/// Time budgets the caller does not supply. Bound to configuration section
/// <c>Connectors:Timeouts</c>.
///
/// <para>Commands and transfers carry their own timeouts on <c>RemoteCommand</c> and
/// <c>FileTransfer</c>, because only the caller knows whether it is running <c>id -u</c> or a
/// distribution upgrade. Connectivity probing has no such payload, so its budget was a literal 15
/// seconds compiled into two connectors — untunable in production and, more immediately, untestable:
/// any test of it had to actually wait fifteen seconds.</para>
/// </summary>
public sealed class ConnectorTimeoutOptions
{
    public const string SectionName = "Connectors:Timeouts";

    /// <summary>Budget for <c>TestConnectivityAsync</c> — reach the host and authenticate.</summary>
    public TimeSpan Connectivity { get; set; } = TimeSpan.FromSeconds(15);

    public void Validate()
    {
        if (Connectivity <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(Connectivity), Connectivity,
                "Every remote operation must be time-bounded (CLAUDE.md NEVER #5).");
        }
    }
}
