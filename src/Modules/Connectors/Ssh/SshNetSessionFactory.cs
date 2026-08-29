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
    private readonly ConnectorTimeoutOptions _timeouts;

    public SshNetSessionFactory(
        ConnectorSecurityOptions? security = null, ConnectorTimeoutOptions? timeouts = null)
    {
        _security = security ?? new ConnectorSecurityOptions();
        _timeouts = timeouts ?? new ConnectorTimeoutOptions();
    }

    /// <summary>
    /// Confirms the endpoint is answering before the SSH exchange begins.
    ///
    /// <para>This is what lets reachability and authentication be judged separately. A host that
    /// will not complete a TCP handshake in a few seconds is unreachable, and saying so immediately
    /// is both more accurate and far cheaper than holding a connection slot for the whole
    /// authentication budget — at 10,000 endpoints that difference is the scaling wall.</para>
    ///
    /// <para>Conversely, once the host HAS answered, exceeding the remaining budget is a genuine
    /// timeout rather than a reachability problem, and a rejection inside it can be reported as what
    /// it is. Previously a single budget covered both, so a slow rejection was indistinguishable
    /// from an unreachable host.</para>
    ///
    /// <para>A port that accepts but whose sshd is wedged correctly falls through to the
    /// authentication budget and reports <c>Timeout</c> — the honest answer, since the host did
    /// answer.</para>
    /// </summary>
    private async Task EnsureReachableAsync(string host, int port, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(_timeouts.Reachability);

        try
        {
            var addresses = await System.Net.Dns.GetHostAddressesAsync(host, deadline.Token).ConfigureAwait(false);
            if (addresses.Length == 0)
            {
                throw new ConnectorConnectException(
                    ConnectorOutcome.Unreachable, $"'{host}' did not resolve to any address.");
            }

            // Every resolved address is attempted CONCURRENTLY and the first success wins.
            //
            // Sequential attempts — which is what TcpClient.ConnectAsync(host, port) does — let one
            // dead address consume the entire budget before the next is tried. That is not a corner
            // case: a dual-stack host whose IPv6 address is unroutable is ordinary, and on Windows
            // "localhost" resolves to ::1 first. A sequential probe against such a host reports
            // Unreachable while an ordinary ssh to the same name connects without trouble, which is
            // precisely the misdiagnosis this whole split exists to remove.
            using var firstSuccess = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var attempts = addresses
                .Select(address => TryConnectAsync(address, port, firstSuccess.Token))
                .ToList();

            while (attempts.Count > 0)
            {
                var finished = await Task.WhenAny(attempts).ConfigureAwait(false);
                attempts.Remove(finished);

                if (await finished.ConfigureAwait(false))
                {
                    await firstSuccess.CancelAsync().ConfigureAwait(false); // abandon the stragglers
                    return;
                }
            }

            throw new ConnectorConnectException(
                ConnectorOutcome.Unreachable,
                $"No resolved address for '{host}' accepted a connection on port {port}.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ConnectorConnectException(
                ConnectorOutcome.Unreachable,
                $"Endpoint did not accept a connection within {_timeouts.Reachability.TotalSeconds:0.#}s.");
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            throw new ConnectorConnectException(
                ConnectorOutcome.Unreachable, "Endpoint could not be reached over SSH.", ex);
        }
    }

    /// <summary>True if this address accepted a connection; false for any failure, including cancellation.</summary>
    private static async Task<bool> TryConnectAsync(System.Net.IPAddress address, int port, CancellationToken ct)
    {
        try
        {
            using var probe = new System.Net.Sockets.TcpClient(address.AddressFamily);
            await probe.ConnectAsync(address, port, ct).ConfigureAwait(false);
            return probe.Connected;
        }
        catch
        {
            // Deliberately total: one address failing says nothing about the others, and the caller
            // reports Unreachable only once every attempt has failed.
            return false;
        }
    }

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
        // Reachability first, on its own short budget, so an unanswering host is reported as
        // Unreachable at once instead of consuming the authentication budget.
        await EnsureReachableAsync(destination.Host, destination.Port, ct).ConfigureAwait(false);

        var client = await AuthenticateAsync(
            destination, destination.Host, destination.Port, resolve, timeout, ct).ConfigureAwait(false);

        return new SshNetSession(client, client.ConnectionInfo);
    }

    /// <summary>
    /// Walks a bastion chain: the first hop is reached over a real socket, and every hop after it —
    /// and finally the destination — is reached through a local port forwarded over the hop before.
    ///
    /// <para><b>This used to be an indexer under a comment claiming a loop</b> (D-306). A two-hop
    /// chain would have connected through the first jump host, ignored the second and reported
    /// success, so it was refused by name instead. That refusal was then unreachable from any real
    /// target, because <c>EndpointTarget.Bastion</c> is a single hop; <see cref="BastionChain"/> is
    /// what made the case expressible, and this is the loop the old comment described.</para>
    ///
    /// <para><b>No arbitrary depth cap.</b> A number would be policy invented here rather than
    /// derived from anything (CLAUDE.md §4.6). The chain is already bounded by configuration — it is
    /// a finite list an operator wrote — and by <paramref name="timeout"/>, which covers the whole
    /// walk rather than each hop, so NEVER #5 holds however long the chain is.</para>
    /// </summary>
    private async Task<ISshSession> ConnectThroughBastionAsync(
        ConnectionPlan plan, CredentialResolver resolve, TimeSpan timeout, CancellationToken ct)
    {
        // Only the FIRST hop is probed. Every later leg is dialled at 127.0.0.1 against a listener
        // SSH.NET has already opened, so a reachability probe there would always succeed and would
        // say nothing about whether the far end is answering — it would just spend budget.
        await EnsureReachableAsync(plan.Hops[0].Host, plan.Hops[0].Port, ct).ConfigureAwait(false);

        // Created in order, disposed in reverse: each forward belongs to the client before it, so
        // tearing down an outer client first would strand the inner one on a dead transport.
        var opened = new List<IDisposable>();
        try
        {
            SshClient? previous = null;

            foreach (var hop in plan.Hops)
            {
                // The first hop is a real address; every later one is reached through the tunnel the
                // previous hop is carrying. This is the only place the two differ.
                var (host, port) = previous is null
                    ? (hop.Host, hop.Port)
                    : Forward(previous, hop.Host, hop.Port, opened);

                previous = await AuthenticateAsync(hop, host, port, resolve, timeout, ct).ConfigureAwait(false);
                opened.Add(previous);
            }

            var (destHost, destPort) = Forward(previous!, plan.Destination.Host, plan.Destination.Port, opened);
            var client = await AuthenticateAsync(
                plan.Destination, destHost, destPort, resolve, timeout, ct).ConfigureAwait(false);

            // The session owns the whole chain: disposing it tears down every forward and every
            // intermediate client, innermost first.
            opened.Reverse();
            return new SshNetSession(client, client.ConnectionInfo, [.. opened]);
        }
        catch
        {
            for (var i = opened.Count - 1; i >= 0; i--)
            {
                try { opened[i].Dispose(); }
                catch { /* unwinding a half-built chain must not mask the original failure */ }
            }
            throw;
        }
    }

    /// <summary>
    /// Opens a local forward on <paramref name="through"/> to <paramref name="host"/>:<paramref name="port"/>
    /// and returns the loopback address the next leg dials. Port 0 lets the OS choose, so concurrent
    /// chains never collide on a fixed local port.
    /// </summary>
    private static (string Host, int Port) Forward(
        SshClient through, string host, int port, List<IDisposable> opened)
    {
        var forward = new ForwardedPortLocal("127.0.0.1", 0, host, (uint)port);
        opened.Add(forward);
        through.AddForwardedPort(forward);
        forward.Start();
        return ("127.0.0.1", (int)forward.BoundPort);
    }

    /// <summary>
    /// Resolves one hop's credential, authenticates at <paramref name="host"/>:<paramref name="port"/>,
    /// and disposes the secret before returning — key material never outlives the leg it authenticated
    /// (NEVER #1/#2). Each hop resolves its OWN reference: reusing the target's credential to reach a
    /// jump host would be a silent authorization change.
    /// </summary>
    private async Task<SshClient> AuthenticateAsync(
        HopSpec hop, string host, int port, CredentialResolver resolve, TimeSpan timeout, CancellationToken ct)
    {
        using var credential = await resolve(hop.Credential, ct).ConfigureAwait(false);
        var info = BuildConnectionInfo(host, port, UsernameFor(hop, credential), credential, timeout);

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
        return client;
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
