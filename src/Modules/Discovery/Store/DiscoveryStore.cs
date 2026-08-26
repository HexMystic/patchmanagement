using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Persistence;
using PatchManagement.Contracts.States;
using PatchManagement.Persistence.Entities;

namespace PatchManagement.Discovery.Store;

/// <summary>
/// The <see cref="IDiscoveryStore"/> over <see cref="AppDbContext"/>.
/// </summary>
internal sealed class DiscoveryStore(AppDbContext db, TimeProvider time) : IDiscoveryStore
{
    public async Task<Guid> OpenRunAsync(SweepRequest request, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var run = new DiscoveryRun
        {
            Id = Guid.NewGuid(),
            TenantId = request.TenantId,
            StartedAt = now,
            CompletedAt = null,
            Outcome = DiscoveryRunOutcomes.Running,
            RequestedRanges = JsonSerializer.Serialize(request.Ranges),
            RequestedPorts = JsonSerializer.Serialize(request.Ports ?? []),
            RefusedRanges = "[]",
            CreatedAt = now,
        };

        db.DiscoveryRuns.Add(run);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return run.Id;
    }

    public async Task CloseRunAsync(
        Guid runId, SweepResult result, int hostsFound, CancellationToken ct)
    {
        var run = await db.DiscoveryRuns.SingleAsync(r => r.Id == runId, ct).ConfigureAwait(false);

        run.Outcome = OutcomeName(result.Outcome);
        run.CompletedAt = time.GetUtcNow();
        run.AddressesProbed = result.AddressesProbed;
        run.HostsFound = hostsFound;
        run.RefusedRanges = JsonSerializer.Serialize(
            result.Refused.Select(r => new { range = r.Range, reason = r.Reason }));

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<Guid>> UpsertCandidatesAsync(
        Guid runId, IReadOnlyList<DiscoveredHost> hosts, CancellationToken ct)
    {
        var run = await db.DiscoveryRuns.SingleAsync(r => r.Id == runId, ct).ConfigureAwait(false);
        var now = time.GetUtcNow();
        var ids = new List<Guid>();

        // Opened through EF so RlsConnectionInterceptor fires and sets app.tenant_id on this exact
        // connection. Issuing the upsert on a connection opened any other way would run it with the
        // GUC unset, which the policy treats as deny-all — the insert would fail closed rather than
        // leak, but it would fail.
        await db.Database.OpenConnectionAsync(ct).ConfigureAwait(false);
        try
        {
            foreach (var host in hosts)
            {
                // One candidate per OPEN PORT, not per address (ADR 0024). The lab forces this: five
                // containers share 127.0.0.1 and are distinguishable only by port. It over-splits a
                // multi-protocol host, which is the direction that loses nothing.
                foreach (var port in host.OpenPorts)
                {
                    ids.Add(await UpsertOneAsync(run.TenantId, host.Address, port, now, ct)
                        .ConfigureAwait(false));
                }
            }
        }
        finally
        {
            await db.Database.CloseConnectionAsync().ConfigureAwait(false);
        }

        for (var i = 0; i < ids.Count; i++)
        {
            db.AssetEvidence.Add(new AssetEvidence
            {
                Id = Guid.NewGuid(),
                TenantId = run.TenantId,
                AssetId = ids[i],
                Source = AssetSources.Discovery,
                Present = true,
                DiscoveryRunId = runId,
                ObservedAt = now,
                Address = Flatten(hosts)[i].Address,
                Port = Flatten(hosts)[i].Port,
                Detail = JsonSerializer.Serialize(new { openPorts = Flatten(hosts)[i].AllOpenPorts }),
                CreatedAt = now,
            });
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        ids.Sort();
        return ids;
    }

    /// <summary>
    /// Insert-or-update on the discovery natural key, returning the id of the row that now
    /// represents this endpoint — the EXISTING id when one was already there.
    ///
    /// <para><b>Raw SQL, and not for performance.</b> The key is a PARTIAL unique index, and
    /// <c>ON CONFLICT</c> can only infer one by repeating its predicate. EF has no expression for
    /// that, and the read-then-write alternative it would force has a race: two concurrent runs both
    /// see no row and both insert, and one gets a 23505 that the caller has to unpick. HARD-PROBLEMS
    /// #6 makes retries a design assumption, so the atomic form is the one that matches the
    /// contract.</para>
    ///
    /// <para><c>DO UPDATE</c> rather than <c>DO NOTHING</c>: the latter returns no row, so the
    /// caller learns nothing and would have to SELECT again — and <c>last_seen</c> would never
    /// advance, making every live host read as abandoned (HARD-PROBLEMS #10).</para>
    ///
    /// <para><b>The inference predicate repeats the index predicate in FULL</b>, including the two
    /// NULL clauses. Postgres infers a partial index only when the <c>ON CONFLICT</c> predicate
    /// implies the index's, and its prover does not accept a prefix: naming only
    /// <c>source = 'discovery'</c> fails with <c>42P10, no unique or exclusion constraint matching
    /// the ON CONFLICT specification</c>. Any change to <c>ux_assets_discovery_candidate</c> has to
    /// be mirrored here — and would fail loudly, not silently, which is why this is safe to state
    /// rather than guard.</para>
    /// </summary>
    private async Task<Guid> UpsertOneAsync(
        Guid tenantId, string address, int port, DateTimeOffset now, CancellationToken ct)
    {
        await using var cmd = db.Database.GetDbConnection().CreateCommand();
        cmd.CommandText = """
            INSERT INTO assets
                (id, tenant_id, hostname, ip, endpoint_port, managed, source, state,
                 last_seen, created_at, updated_at)
            VALUES
                (@id, @tenant_id, @hostname, @ip, @endpoint_port, false, @source, @state,
                 @now, @now, @now)
            ON CONFLICT (tenant_id, ip, endpoint_port)
                WHERE source = 'discovery' AND ip IS NOT NULL AND endpoint_port IS NOT NULL
            DO UPDATE SET last_seen = EXCLUDED.last_seen,
                          updated_at = EXCLUDED.updated_at
            RETURNING id
            """;

        AddParameter(cmd, "id", Guid.NewGuid());
        AddParameter(cmd, "tenant_id", tenantId);
        // A sweep never learns a hostname — it does not log in — so the address is what is recorded.
        // Inventory replaces it once something has actually asked the host its name (slice 3).
        AddParameter(cmd, "hostname", address);
        AddParameter(cmd, "ip", address);
        AddParameter(cmd, "endpoint_port", port);
        AddParameter(cmd, "source", AssetSources.Discovery);
        // Honest state: something answered a TCP probe, which is not a successful scan
        // (HARD-PROBLEMS #8 — "couldn't check" is never collapsed into compliant).
        AddParameter(cmd, "state", Contracts.States.EndpointState.ScanFailed.ToDbValue());
        AddParameter(cmd, "now", now);

        var id = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return (Guid)id!;
    }

    private static void AddParameter(System.Data.Common.DbCommand cmd, string name, object value)
    {
        var p = cmd.CreateParameter();
        p.ParameterName = name;
        p.Value = value;
        cmd.Parameters.Add(p);
    }

    /// <summary>The (address, port) pairs a host expands to, in the order candidates are upserted.</summary>
    private static IReadOnlyList<(string Address, int Port, IReadOnlyList<int> AllOpenPorts)> Flatten(
        IReadOnlyList<DiscoveredHost> hosts) =>
        [.. hosts.SelectMany(h => h.OpenPorts.Select(p => (h.Address, Port: p, AllOpenPorts: h.OpenPorts)))];

    private static string OutcomeName(SweepOutcome outcome) => outcome switch
    {
        SweepOutcome.Ok => DiscoveryRunOutcomes.Ok,
        SweepOutcome.RefusedByPolicy => DiscoveryRunOutcomes.RefusedByPolicy,
        SweepOutcome.InvalidRange => DiscoveryRunOutcomes.InvalidRange,
        _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Unknown sweep outcome."),
    };
}
