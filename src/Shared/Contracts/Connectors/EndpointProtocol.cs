namespace PatchManagement.Contracts.Connectors;

/// <summary>The remote-management protocol used to reach an endpoint (agentless — CLAUDE.md §2).</summary>
public enum EndpointProtocol
{
    /// <summary>Linux — SSH (key auth), sudo for privileged ops, SFTP for transfers.</summary>
    Ssh,

    /// <summary>Windows — WinRM/HTTPS + PowerShell Remoting.</summary>
    WinRm,
}

/// <summary>Default TCP ports per protocol.</summary>
public static class EndpointProtocolDefaults
{
    public const int SshPort = 22;
    public const int WinRmHttpsPort = 5986;

    public static int DefaultPort(this EndpointProtocol protocol) => protocol switch
    {
        EndpointProtocol.Ssh => SshPort,
        EndpointProtocol.WinRm => WinRmHttpsPort,
        _ => throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "Unknown protocol."),
    };
}
