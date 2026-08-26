using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PatchManagement.Contracts.Discovery;

namespace PatchManagement.Discovery.Sweep;

/// <summary>
/// Expands the requested CIDR ranges and probes every address for open management ports.
///
/// <para><b>Two gates stand in front of any socket, and both are all-or-nothing.</b> A range must
/// first be interpretable as a bounded IPv4 block, then be inside the scope this deployment
/// declared (<see cref="DiscoveryTargetPolicy"/>). If any requested range fails either gate,
/// <b>nothing at all is probed</b> — not even the ranges that passed.</para>
///
/// <para>Sweeping the acceptable ranges and quietly dropping the rest is the tempting behaviour and
/// the wrong one: it reports a coverage gap as a clean result, and coverage gaps are precisely what
/// this phase exists to surface. Phase 5 shipped that shape three times over — a connector that
/// returned an empty batch with a green status and an advanced cursor — and it was invisible until
/// someone went looking for content that should have been there.</para>
/// </summary>
internal sealed class NetworkSweeper : INetworkSweeper
{
    private readonly DiscoverySweepOptions _options;
    private readonly DiscoveryTargetPolicy _policy;
    private readonly IPortProbe _probe;
    private readonly ILogger<NetworkSweeper> _logger;

    public NetworkSweeper(
        IOptions<DiscoverySweepOptions> options,
        IOptions<DiscoverySecurityOptions> security,
        IPortProbe probe,
        ILogger<NetworkSweeper> logger)
    {
        _options = options.Value;
        _probe = probe;
        _logger = logger;

        // Derived purely from configuration, so the sweeper owns it rather than taking it injected.
        // Building it once here also means a malformed allowlist entry is reported once at
        // construction, not on every sweep.
        _policy = new DiscoveryTargetPolicy(security.Value, logger);
    }

    public async Task<SweepResult> ScanAsync(SweepRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);

        // A caller bug, not a runtime outcome: discovery results are tenant-scoped data, and a
        // sweep with no tenant has no one to attribute its findings to.
        if (request.TenantId == Guid.Empty)
        {
            throw new ArgumentException(
                "A sweep must carry a tenant - discovery results are tenant-scoped (CLAUDE.md 4.1).",
                nameof(request));
        }

        if (request.Ranges.Count == 0)
        {
            throw new ArgumentException("A sweep must name at least one range.", nameof(request));
        }

        var blocks = new List<CidrBlock>(request.Ranges.Count);
        var rejected = new List<RefusedRange>();

        foreach (var range in request.Ranges)
        {
            if (CidrBlock.TryParse(range, _options.MaxHostsPerRange, out var block, out var reason))
            {
                blocks.Add(block);
            }
            else
            {
                rejected.Add(new RefusedRange(range ?? string.Empty, reason!));
            }
        }

        // All-or-nothing. A partially-swept estate reported as a success is a coverage gap that
        // looks like a clean bill of health, which is the failure mode this whole phase exists to
        // eliminate.
        if (rejected.Count > 0)
        {
            _logger.LogWarning(
                "Sweep refused: {Count} range(s) could not be interpreted as bounded IPv4 blocks.",
                rejected.Count);
            return SweepResult.Refuse(SweepOutcome.InvalidRange, rejected);
        }

        // Gate two: NEVER #4. Evaluated over every parsed block BEFORE a single socket is opened,
        // which is what makes the refusal meaningful — a policy consulted per-address mid-sweep
        // would already have contacted the hosts it then declined to contact.
        var outOfScope = blocks
            .Where(b => !_policy.Permits(b))
            .Select(b => new RefusedRange(b.Text, _policy.RefusalReason(b)))
            .ToList();

        if (outOfScope.Count > 0)
        {
            _logger.LogWarning(
                "Sweep refused by target policy: {Refused} of {Total} requested range(s) fall "
                + "outside Discovery:Security:AllowedTargets. Nothing was probed.",
                outOfScope.Count, blocks.Count);
            return SweepResult.Refuse(SweepOutcome.RefusedByPolicy, outOfScope);
        }

        var ports = request.Ports is { Count: > 0 } p ? p : [.. _options.ManagementPorts];
        return await ProbeAsync(blocks, ports, ct).ConfigureAwait(false);
    }

    private async Task<SweepResult> ProbeAsync(
        IReadOnlyList<CidrBlock> blocks, IReadOnlyList<int> ports, CancellationToken ct)
    {
        var found = new ConcurrentBag<DiscoveredHost>();
        var probed = 0;

        using var gate = new SemaphoreSlim(_options.MaxConcurrentProbes);
        var work = new List<Task>();

        foreach (var address in blocks.SelectMany(b => b.Addresses()).Select(a => a.ToString()))
        {
            Interlocked.Increment(ref probed);
            work.Add(ProbeAddressAsync(address, ports, found, gate, ct));
        }

        await Task.WhenAll(work).ConfigureAwait(false);

        var hosts = found
            .OrderBy(h => h.Address, StringComparer.Ordinal)
            .ToList();

        return SweepResult.Swept(hosts, probed);
    }

    private async Task ProbeAddressAsync(
        string address,
        IReadOnlyList<int> ports,
        ConcurrentBag<DiscoveredHost> found,
        SemaphoreSlim gate,
        CancellationToken ct)
    {
        var open = new List<int>();
        var fastest = TimeSpan.MaxValue;

        foreach (var port in ports)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var result = await _probe
                    .ProbeAsync(address, port, _options.ProbeTimeout, ct)
                    .ConfigureAwait(false);

                if (result.Open)
                {
                    open.Add(port);
                    if (result.Elapsed < fastest)
                    {
                        fastest = result.Elapsed;
                    }
                }
            }
            finally
            {
                gate.Release();
            }
        }

        if (open.Count > 0)
        {
            open.Sort();
            found.Add(new DiscoveredHost
            {
                Address = address,
                OpenPorts = open,
                Latency = fastest == TimeSpan.MaxValue ? TimeSpan.Zero : fastest,
            });
        }
    }
}
