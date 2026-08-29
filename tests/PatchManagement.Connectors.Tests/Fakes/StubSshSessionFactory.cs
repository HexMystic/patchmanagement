using PatchManagement.Connectors.Connection;
using PatchManagement.Connectors.Ssh;

namespace PatchManagement.Connectors.Tests.Fakes;

/// <summary>
/// Hands out a pre-built <see cref="ISshSession"/> instead of opening a socket, and — importantly —
/// invokes the supplied <see cref="CredentialResolver"/> the way the real factory does.
///
/// <para>That last part is what makes credential-lifecycle assertions meaningful: if the stub simply
/// ignored the resolver, a test could "prove" the connector disposes credentials it never actually
/// resolved. The real factory resolves each hop's secret at connect time, so this does too.</para>
/// </summary>
internal sealed class StubSshSessionFactory : ISshSessionFactory
{
    private readonly Func<ISshSession> _session;
    private readonly Exception? _throw;

    public StubSshSessionFactory(Func<ISshSession> session) => _session = session;

    /// <summary>Fails every connect, for asserting the auth-failure and cleanup paths.</summary>
    public StubSshSessionFactory(Exception thrown)
    {
        _throw = thrown;
        _session = () => throw new InvalidOperationException("unreachable");
    }

    public int ConnectAttempts { get; private set; }

    /// <summary>The plans it was asked to connect, so bastion wiring can be asserted without a socket.</summary>
    public List<ConnectionPlan> Plans { get; } = [];

    /// <summary>The host-key stores it was handed, so wiring can be asserted without a socket.</summary>
    public List<IHostKeyStore?> HostKeyStores { get; } = [];

    public async Task<ISshSession> ConnectAsync(
        ConnectionPlan plan,
        CredentialResolver resolve,
        IHostKeyStore? hostKeys,
        TimeSpan connectTimeout,
        CancellationToken ct)
    {
        HostKeyStores.Add(hostKeys);
        ConnectAttempts++;
        Plans.Add(plan);

        // Resolve every hop's credential exactly as the real factory does, disposing each — the
        // behaviour the lifecycle tests are actually about.
        foreach (var hop in plan.Hops)
        {
            using var hopCredential = await resolve(hop.Credential, ct).ConfigureAwait(false);
        }

        using (var destination = await resolve(plan.Destination.Credential, ct).ConfigureAwait(false))
        {
            if (_throw is not null) throw _throw;
        }

        return _session();
    }
}
