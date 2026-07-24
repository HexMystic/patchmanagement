using PatchManagement.Contracts.Credentials;

namespace PatchManagement.Connectors.Model;

/// <summary>
/// A jump/bastion host the connector tunnels through to reach the target.
///
/// Per ADR 0003 this is <b>configuration, not code</b>: the connector never knows whether a
/// hop is an Azure Bastion, an AWS SSM proxy, an on-prem jump box, or anything else. It is just
/// "another host, reached first". Presence of this value on an <see cref="EndpointTarget"/>
/// selects the tunnelled connection plan; absence selects the direct plan. No cloud provider is
/// ever referenced in connector logic.
/// </summary>
public sealed record BastionHop(
    string Host,
    int Port,
    CredentialRef Credential,
    string? Username = null);
