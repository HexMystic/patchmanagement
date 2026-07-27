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
/// Host-key policy here accepts the presented key (the dev lab). Production pins/verifies host keys
/// via <see cref="SshClient.HostKeyReceived"/>; that is a wiring change, not a connector change.
/// </summary>
internal sealed class SshNetSessionFactory : ISshSessionFactory
{
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

    private static async Task<ISshSession> ConnectDirectAsync(
        HopSpec destination, CredentialResolver resolve, TimeSpan timeout, CancellationToken ct)
    {
        using var credential = await resolve(destination.Credential, ct).ConfigureAwait(false);
        var user = UsernameFor(destination, credential);
        var info = BuildConnectionInfo(destination.Host, destination.Port, user, credential, timeout);

        var client = new SshClient(info);
        AcceptPresentedHostKey(client);
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

    private static async Task<ISshSession> ConnectThroughBastionAsync(
        ConnectionPlan plan, CredentialResolver resolve, TimeSpan timeout, CancellationToken ct)
    {
        // ConnectionPlanner emits a single hop today; the loop keeps the code honest for chains.
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
                AcceptPresentedHostKey(bastion);
                await bastion.ConnectAsync(ct).ConfigureAwait(false);
            }

            forward = new ForwardedPortLocal("127.0.0.1", 0, plan.Destination.Host, (uint)plan.Destination.Port);
            bastion.AddForwardedPort(forward);
            forward.Start();

            using var destCredential = await resolve(plan.Destination.Credential, ct).ConfigureAwait(false);
            var destUser = UsernameFor(plan.Destination, destCredential);
            var destInfo = BuildConnectionInfo("127.0.0.1", (int)forward.BoundPort, destUser, destCredential, timeout);

            var client = new SshClient(destInfo);
            AcceptPresentedHostKey(client);
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

    private static void AcceptPresentedHostKey(SshClient client) =>
        client.HostKeyReceived += (_, e) => e.CanTrust = true;

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
