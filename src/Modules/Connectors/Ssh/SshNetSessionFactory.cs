using System.Net.Sockets;
using PatchManagement.Connectors.Connection;
using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Credentials;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace PatchManagement.Connectors.Ssh;

/// <summary>
/// Builds real SSH.NET sessions. Direct connections are the tested path (lab fleet). When the plan
/// carries a bastion hop the factory connects the jump host and forwards a local port to the target,
/// then authenticates the target over that tunnel — the connector above is unaware which path was
/// taken (ADR 0003). Connect/auth failures are translated to honest <see cref="ConnectorOutcome"/>s.
///
/// Host-key policy is configuration (<see cref="ConnectorSecurityOptions"/>) and refuses unknown
/// keys by default. A verified-key store is deferred to Phase 4 with asset persistence; until then
/// this flag is what keeps the connector off a real fleet.
/// </summary>
internal sealed class SshNetSessionFactory : ISshSessionFactory
{
    private readonly ConnectorSecurityOptions _security;

    public SshNetSessionFactory(ConnectorSecurityOptions? security = null) =>
        _security = security ?? new ConnectorSecurityOptions();

    public async Task<ISshSession> ConnectAsync(
        ConnectionPlan plan,
        CredentialResolver resolve,
        TimeSpan connectTimeout,
        CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(connectTimeout);

        try
        {
            return plan.IsDirect
                ? await ConnectDirectAsync(plan.Destination, resolve, connectTimeout, cts.Token).ConfigureAwait(false)
                : await ConnectThroughBastionAsync(plan, resolve, connectTimeout, cts.Token).ConfigureAwait(false);
        }
        catch (ConnectorConnectException)
        {
            throw;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // caller-initiated cancellation propagates unchanged
        }
        catch (Exception ex)
        {
            throw Map(ex);
        }
    }

    private async Task<ISshSession> ConnectDirectAsync(
        HopSpec destination, CredentialResolver resolve, TimeSpan timeout, CancellationToken ct)
    {
        using var credential = await resolve(destination.Credential, ct).ConfigureAwait(false);
        var user = UsernameFor(destination, credential);
        var info = BuildConnectionInfo(destination.Host, destination.Port, user, credential, timeout);

        var client = new SshClient(info);
        ApplyHostKeyPolicy(client);
        try
        {
            await client.ConnectAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            client.Dispose();
            throw;
        }
        return new SshNetSession(client, info);
    }

    private async Task<ISshSession> ConnectThroughBastionAsync(
        ConnectionPlan plan, CredentialResolver resolve, TimeSpan timeout, CancellationToken ct)
    {
        // Exactly one hop is supported. The previous comment here claimed "the loop keeps the code
        // honest for chains" above an indexer, not a loop — so a two-hop chain would have connected
        // through the first jump host, ignored the second, and reported success. Connecting somewhere
        // the operator did not ask for is the worst available outcome for a misconfigured chain, so
        // it is refused by name instead. Multi-hop support is a deferred item with a named owner.
        if (plan.Hops.Count > 1)
        {
            throw new ConnectorConnectException(
                ConnectorOutcome.ProtocolError,
                $"This connector supports a single bastion hop; the plan specifies {plan.Hops.Count}. "
                + "Multi-hop chains are not implemented — configure one jump host, or chain at the "
                + "SSH-config level on the bastion itself.");
        }

        var hop = plan.Hops[0];
        SshClient? bastion = null;
        ForwardedPortLocal? forward = null;
        try
        {
            using (var hopCredential = await resolve(hop.Credential, ct).ConfigureAwait(false))
            {
                var hopUser = UsernameFor(hop, hopCredential);
                var hopInfo = BuildConnectionInfo(hop.Host, hop.Port, hopUser, hopCredential, timeout);
                bastion = new SshClient(hopInfo);
                ApplyHostKeyPolicy(bastion);
                await bastion.ConnectAsync(ct).ConfigureAwait(false);
            }

            forward = new ForwardedPortLocal("127.0.0.1", 0, plan.Destination.Host, (uint)plan.Destination.Port);
            bastion.AddForwardedPort(forward);
            forward.Start();

            using var destCredential = await resolve(plan.Destination.Credential, ct).ConfigureAwait(false);
            var destUser = UsernameFor(plan.Destination, destCredential);
            var destInfo = BuildConnectionInfo("127.0.0.1", (int)forward.BoundPort, destUser, destCredential, timeout);

            var client = new SshClient(destInfo);
            ApplyHostKeyPolicy(client);
            await client.ConnectAsync(ct).ConfigureAwait(false);

            // The session owns the tunnel: disposing it tears down the forward and the bastion.
            return new SshNetSession(client, destInfo, forward, bastion);
        }
        catch
        {
            forward?.Dispose();
            bastion?.Dispose();
            throw;
        }
    }

    private static ConnectionInfo BuildConnectionInfo(
        string host, int port, string username, ResolvedCredential credential, TimeSpan timeout)
    {
        var keyFile = ReadPrivateKey(credential);
        var auth = new PrivateKeyAuthenticationMethod(username, keyFile);
        return new ConnectionInfo(host, port, username, auth)
        {
            Timeout = timeout,
            RetryAttempts = 1,
        };
    }

    private static PrivateKeyFile ReadPrivateKey(ResolvedCredential credential)
    {
        if (credential.Kind != CredentialKind.SshKey)
            throw new ConnectorConnectException(ConnectorOutcome.AuthFailed, "SSH connector requires an SSH key credential.");

        // Copy the secret to a stream for parsing, then zero the transient buffer immediately.
        var bytes = credential.Secret.ToArray();
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            return new PrivateKeyFile(stream);
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    private static string UsernameFor(HopSpec hop, ResolvedCredential credential) =>
        hop.Username
        ?? credential.Username
        ?? throw new ConnectorConnectException(ConnectorOutcome.AuthFailed, "No SSH username was supplied on the credential or hop.");

    /// <summary>
    /// Applies the configured host-key policy.
    ///
    /// <para>This used to be <c>e.CanTrust = true</c> unconditionally, which authenticates whatever
    /// answers on the target's address and then sends it a private key. The decision now comes from
    /// configuration and defaults to refusing (see <see cref="ConnectorSecurityOptions"/>), so a
    /// deployment that has not consciously opted in cannot be silently intercepted.</para>
    /// </summary>
    private void ApplyHostKeyPolicy(SshClient client) =>
        client.HostKeyReceived += (_, e) => e.CanTrust = _security.AllowUnknownHostKeys;

    private static ConnectorConnectException Map(Exception ex) => ex switch
    {
        SshAuthenticationException => new(ConnectorOutcome.AuthFailed, "SSH authentication was rejected.", ex),
        SshConnectionException or SocketException or ProxyException =>
            new(ConnectorOutcome.Unreachable, "Endpoint could not be reached over SSH.", ex),
        SshOperationTimeoutException or OperationCanceledException or TimeoutException =>
            new(ConnectorOutcome.Timeout, "SSH connection timed out.", ex),
        _ => new(ConnectorOutcome.ProtocolError, $"SSH connection failed ({ex.GetType().Name}).", ex),
    };
}
