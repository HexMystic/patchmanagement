using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Model;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Ssh;

/// <summary>Resolves a credential reference to in-memory secret material at the moment of use.</summary>
internal delegate Task<ResolvedCredential> CredentialResolver(CredentialRef reference, CancellationToken ct);

/// <summary>
/// Establishes an authenticated <see cref="ISshSession"/> for a <see cref="ConnectionPlan"/>,
/// tunnelling through any configured bastion hops (the plan decides direct vs jump — no
/// cloud-specific code; ADR 0003). Each hop's credential is resolved on demand via the supplied
/// <see cref="CredentialResolver"/> and disposed inside the factory — secret material never leaves
/// the connect path (NEVER #1/#2). Connection/auth failures surface as a typed
/// <see cref="ConnectorConnectException"/> so callers map them onto honest outcomes without
/// catching transport-specific exception types.
/// </summary>
internal interface ISshSessionFactory
{
    Task<ISshSession> ConnectAsync(
        ConnectionPlan plan,
        CredentialResolver resolve,
        TimeSpan connectTimeout,
        CancellationToken ct);
}

/// <summary>
/// A connect/authenticate failure translated to an honest <see cref="ConnectorOutcome"/>. Carries
/// no secret material; its message is safe to log.
/// </summary>
internal sealed class ConnectorConnectException(ConnectorOutcome outcome, string detail, Exception? inner = null)
    : Exception(detail, inner)
{
    public ConnectorOutcome Outcome { get; } = outcome;
}
