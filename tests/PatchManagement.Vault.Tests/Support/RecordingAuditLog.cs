using System.Collections.Concurrent;
using PatchManagement.Contracts.Auditing;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// Records what was appended and — the point of this double — the <see cref="CancellationToken"/>
/// each append was handed. An audit row that compensates for work already committed must not be
/// cancellable out from under it (re-review H-B), and the token is the only place that guarantee is
/// observable from outside.
/// </summary>
public sealed class RecordingAuditLog : IAuditLog
{
    private readonly ConcurrentQueue<(AuditEntry Entry, CancellationToken Token)> _appends = new();

    public IReadOnlyList<(AuditEntry Entry, CancellationToken Token)> Appends => [.. _appends];

    public Task AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        _appends.Enqueue((entry, ct));
        return Task.CompletedTask;
    }
}
