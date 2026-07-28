using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Contracts.Connectors;

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

    /// <summary>
    /// Optional second credential for privilege elevation — the <c>sudo</c> password on Linux.
    ///
    /// <para>Why a second reference rather than a second secret on one credential: a login key and a
    /// sudo password are two secrets belonging to one logical identity, and the frozen
    /// <see cref="ResolvedCredential"/> carries exactly one <c>byte[]</c> (review finding M7). Rather
    /// than change a frozen contract, the connector resolves two references and disposes both. Each
    /// is stored, rotated and audited independently, which is arguably the more honest model anyway.</para>
    ///
    /// <para>Null means no elevation secret is available: an elevated command then runs
    /// <c>sudo -n</c> (non-interactive) and fails honestly if the host demands a password, rather
    /// than hanging on a prompt no one can answer.</para>
    ///
    /// <para><b>Untested against real hardware.</b> The dev lab grants <c>NOPASSWD</c> sudo and locks
    /// the account password, so the fleet cannot exercise this path at all; it is proven against a
    /// fake session only. See docs/phases/phase-3.md.</para>
    /// </summary>
    public CredentialRef? PrivilegeCredential { get; init; }

    /// <summary>Optional jump host. Null = direct connection. Non-null = tunnel through it.</summary>
    public BastionHop? Bastion { get; init; }

    /// <summary>Optional stable asset id for correlation/logging (never a secret).</summary>
    public string? AssetId { get; init; }

    /// <summary>
    /// Suppresses the double-hop guard. Default <c>false</c>: a command or transfer that needs onward
    /// authentication is refused as <see cref="ConnectorOutcome.DoubleHopRequired"/> rather than
    /// attempted (HARD-PROBLEMS #9).
    ///
    /// <para><b>It does NOT delegate anything.</b> Despite the name, no CredSSP or constrained-Kerberos
    /// delegation is configured, negotiated or performed anywhere in this connector — the flag's only
    /// effect is to skip the refusal. Setting it therefore does not make a second hop work; it
    /// converts an honest, immediate <c>DoubleHopRequired</c> into whatever the endpoint does with a
    /// session that cannot authenticate onward, which is the opaque hang or access-denied that
    /// HARD-PROBLEMS #9 exists to prevent. Leave it <c>false</c> unless you are deliberately trading a
    /// clear refusal for an unclear failure.</para>
    ///
    /// <para>Actually implementing delegation is <b>D-304, owner Phase 8</b>. Until it closes, the
    /// supported way to avoid a double hop is the one the connector is built around: push the payload
    /// to the target first, then run it locally.</para>
    /// </summary>
    public bool AllowCredentialDelegation { get; init; }

    public int EffectivePort => Port > 0 ? Port : Protocol.DefaultPort();
}
