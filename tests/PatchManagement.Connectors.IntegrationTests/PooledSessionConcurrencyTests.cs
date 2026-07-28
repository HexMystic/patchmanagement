using System.Security.Cryptography;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// Concurrent work over ONE pooled session, against ONE host.
///
/// <para><b>The single host is the entire point, and it is what no existing test does.</b>
/// <c>SessionCapTests</c> deliberately targets a different host per operation, documenting that
/// "pointing them all at one host would let the pool serve every one from a single reused transport" —
/// which is true, and is exactly the configuration that broke. <c>SshFleetTests</c> is a theory over
/// five hosts but runs its facts one at a time. So every existing test either had one operation per
/// session or one session per operation, and the case the pool actually promises — several concurrent
/// operations sharing one authenticated transport — was never exercised.</para>
///
/// <para>It does not survive contact: <c>SshNetSession.EnsureSftpAsync</c> checked, disposed, assigned
/// and connected with no synchronisation, so a second borrower disposed the SFTP client the first was
/// still connecting and both ended up on a client that was closed underneath them
/// (<c>SshConnectionException: Client not connected</c>), with the orphan leaked for the process
/// lifetime. Two concurrent pushes to one host is the ordinary shape of a deployment wave.</para>
/// </summary>
[Collection(LabCollection.Name)]
public sealed class PooledSessionConcurrencyTests(LabFixture lab)
{
    private static LabHost Host => LabFleet.All[0];

    /// <summary>
    /// Rounds per race test. A race needs more than one attempt to be evidence: a single round that
    /// happens to pass says only that this run got lucky, and a regression that reappears one time in
    /// four would otherwise land as an occasional red that someone reruns away.
    /// </summary>
    private const int Rounds = 5;

    /// <summary>
    /// Two concurrent transfers to the same host. Both must succeed AND both payloads must survive
    /// byte-for-byte — a hash check, because a transfer corrupted by a client closing underneath it
    /// can still report a plausible length.
    ///
    /// <para><b>The warm-up and the rounds are what make this reproduce, and both are load-bearing.</b>
    /// The race is only reachable while a session's SFTP client does not yet exist. Without a warm-up
    /// the pool serialises session creation, so the first transfer gets a head start of one full SSH
    /// handshake and is usually finished with <c>EnsureSftpAsync</c> before the second arrives — the
    /// bug is real but invisible. Running a plain command first establishes the session WITHOUT
    /// establishing its SFTP client, so both transfers reach that method together. And because a
    /// successful round leaves a connected client behind that every later borrower reuses, each round
    /// needs a fresh pool. A version of this test without those two properties passed against the
    /// unsynchronised code.</para>
    /// </summary>
    [Fact]
    public async Task Two_concurrent_pushes_to_one_host_both_succeed_and_round_trip()
    {
        var target = lab.TargetFor(Host);
        var ct = CancellationToken.None;

        for (var round = 0; round < Rounds; round++)
        {
            var connector = lab.ConnectorWith(lab.Credentials);

            // Establishes the SESSION but not its SFTP client — see the remarks above.
            var warm = await connector.RunAsync(target, new RemoteCommand { CommandLine = "true" }, ct);
            Assert.Equal(ConnectorOutcome.Ok, warm.Outcome);

            var first = (Payload: RandomNumberGenerator.GetBytes(256 * 1024), Path: RemotePath($"a{round}"));
            var second = (Payload: RandomNumberGenerator.GetBytes(256 * 1024), Path: RemotePath($"b{round}"));

            try
            {
                var pushes = await Task.WhenAll(
                    connector.PushAsync(target, Transfer(first.Path, first.Payload), ct),
                    connector.PushAsync(target, Transfer(second.Path, second.Payload), ct));

                Assert.All(pushes, p => Assert.Equal(ConnectorOutcome.Ok, p.Outcome));

                foreach (var (payload, path) in new[] { first, second })
                {
                    var pull = await connector.PullAsync(target, new FileTransfer { RemotePath = path }, ct);

                    Assert.Equal(ConnectorOutcome.Ok, pull.Outcome);
                    Assert.NotNull(pull.Content);
                    Assert.Equal(
                        Convert.ToHexString(SHA256.HashData(payload)),
                        Convert.ToHexString(SHA256.HashData(pull.Content!.Value.ToArray())));
                }
            }
            finally
            {
                await Cleanup(target, first.Path, second.Path);
            }
        }
    }

    /// <summary>
    /// The same race at a width that makes an intermittent failure unmissable. Eight concurrent
    /// transfers over one session; every one must land intact.
    /// </summary>
    [Fact]
    public async Task Many_concurrent_transfers_over_one_pooled_session_all_land_intact()
    {
        const int Width = 8;
        var target = lab.TargetFor(Host);
        var ct = CancellationToken.None;

        var connector = lab.ConnectorWith(lab.Credentials);
        var warm = await connector.RunAsync(target, new RemoteCommand { CommandLine = "true" }, ct);
        Assert.Equal(ConnectorOutcome.Ok, warm.Outcome);

        var payloads = Enumerable.Range(0, Width)
            .Select(i => (Payload: RandomNumberGenerator.GetBytes(64 * 1024), Path: RemotePath($"w{i}")))
            .ToList();

        try
        {
            var pushes = await Task.WhenAll(
                payloads.Select(p => connector.PushAsync(target, Transfer(p.Path, p.Payload), ct)));

            Assert.All(pushes, p => Assert.Equal(ConnectorOutcome.Ok, p.Outcome));

            var pulls = await Task.WhenAll(
                payloads.Select(p => connector.PullAsync(target, new FileTransfer { RemotePath = p.Path }, ct)));

            for (var i = 0; i < Width; i++)
            {
                Assert.Equal(ConnectorOutcome.Ok, pulls[i].Outcome);
                Assert.Equal(
                    Convert.ToHexString(SHA256.HashData(payloads[i].Payload)),
                    Convert.ToHexString(SHA256.HashData(pulls[i].Content!.Value.ToArray())));
            }
        }
        finally
        {
            await Cleanup(target, payloads.Select(p => p.Path).ToArray());
        }
    }

    /// <summary>
    /// Commands and transfers interleaved on the same session — the realistic wave shape, where a
    /// verification command runs while a payload is still being pushed.
    /// </summary>
    [Fact]
    public async Task Commands_and_transfers_interleave_safely_on_one_pooled_session()
    {
        var target = lab.TargetFor(Host);
        var ct = CancellationToken.None;
        var path = RemotePath("mixed");
        var payload = RandomNumberGenerator.GetBytes(128 * 1024);

        var connector = lab.ConnectorWith(lab.Credentials);
        var warm = await connector.RunAsync(target, new RemoteCommand { CommandLine = "true" }, ct);
        Assert.Equal(ConnectorOutcome.Ok, warm.Outcome);

        try
        {
            var work = new List<Task<bool>>
            {
                Run(connector.PushAsync(target, Transfer(path, payload), ct)),
            };

            work.AddRange(Enumerable.Range(0, 6).Select(i => RunCommand(connector, target, $"echo marker-{i}", i, ct)));

            var outcomes = await Task.WhenAll(work);
            Assert.All(outcomes, ok => Assert.True(ok));
        }
        finally
        {
            await Cleanup(target, path);
        }

        static async Task<bool> Run(Task<FileResult> transfer) =>
            (await transfer).Outcome == ConnectorOutcome.Ok;
    }

    private static async Task<bool> RunCommand(
        Connectors.Ssh.SshConnector connector, EndpointTarget target, string commandLine, int index, CancellationToken ct)
    {
        var result = await connector.RunAsync(target, new RemoteCommand { CommandLine = commandLine }, ct);

        return result.Outcome == ConnectorOutcome.Ok
               && result.StandardOutput.Contains($"marker-{index}", StringComparison.Ordinal);
    }

    private static FileTransfer Transfer(string remotePath, byte[] content) =>
        new() { RemotePath = remotePath, Content = content };

    private static string RemotePath(string tag) => $"/tmp/pm-conc-{tag}-{Guid.NewGuid():N}.bin";

    private async Task Cleanup(EndpointTarget target, params string[] paths) =>
        await lab.Connector.RunAsync(
            target,
            new RemoteCommand { CommandLine = $"rm -f {string.Join(' ', paths)}" },
            CancellationToken.None);
}
