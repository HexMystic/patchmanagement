using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Model;

/// <summary>
/// A managed endpoint the connector can reach. Carries host/protocol/port, a credential
/// <b>reference</b> (never a raw secret — resolved lazily via <see cref="ICredentialProvider"/>),
/// and an optional <see cref="BastionHop"/> (direct vs jump is pure configuration; ADR 0003).
///
/// The <see cref="TenantId"/> is present so the connection governor can enforce per-tenant
/// concurrency caps (the scaling wall is connection concurrency, not the DB — CLAUDE.md §2).
/// </summary>
public sealed record EndpointTarget
{
    public required Guid TenantId { get; init; }

    /// <summary>Hostname or IP. In dev this is only ever a localhost lab container (NEVER #4).</summary>
    public required string Host { get; init; }

    public required EndpointProtocol Protocol { get; init; }

    /// <summary>TCP port; defaults to the protocol default when not set.</summary>
    public int Port { get; init; }

    /// <summary>Reference to the stored credential; resolved to memory only at the moment of use.</summary>
    public required CredentialRef Credential { get; init; }

    /// <summary>Optional jump host. Null = direct connection. Non-null = tunnel through it.</summary>
    public BastionHop? Bastion { get; init; }

    /// <summary>Optional stable asset id for correlation/logging (never a secret).</summary>
    public string? AssetId { get; init; }

    /// <summary>
    /// Whether the connector may attempt onward credential delegation (CredSSP / constrained
    /// Kerberos) for a WinRM double-hop. Default <c>false</c>: a required second hop is
    /// <b>surfaced honestly</b> rather than blindly delegated (HARD-PROBLEMS #9).
    /// </summary>
    public bool AllowCredentialDelegation { get; init; }

    public int EffectivePort => Port > 0 ? Port : Protocol.DefaultPort();
}
