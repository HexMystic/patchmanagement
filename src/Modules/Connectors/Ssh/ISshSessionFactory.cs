using PatchManagement.Connectors.Connection;
using PatchManagement.Contracts.Connectors;
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
    /// <param name="hostKeys">
    /// The verified-host-key store consulted at every hop, or <c>null</c> for the pre-D-301 posture
    /// where <c>ConnectorSecurityOptions.AllowUnknownHostKeys</c> is the whole decision.
    ///
    /// <para><b>Required rather than optional on purpose.</b> Defaulting it to <c>null</c> would mean
    /// a caller that forgot it silently downgraded host-key verification to the blanket yes/no this
    /// parameter exists to replace — a failure with no symptom until an endpoint is impersonated.
    /// Passing <c>null</c> has to be a decision someone typed.</para>
    ///
    /// <para>It is a parameter rather than a constructor dependency because the store is
    /// <b>scoped</b> (it reads the request's tenant through <c>AppDbContext</c>) while this factory is
    /// a <b>singleton</b> holding the process-wide connection budget. Capturing it would be the same
    /// captive dependency ADR 0017 records the connectors already hitting once, and resolving a fresh
    /// scope inside the singleton would silently lose the ambient tenant (ADR 0014). The credential
    /// resolver is threaded through for exactly the same reason.</para>
    /// </param>
    Task<ISshSession> ConnectAsync(
        ConnectionPlan plan,
        CredentialResolver resolve,
        IHostKeyStore? hostKeys,
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
