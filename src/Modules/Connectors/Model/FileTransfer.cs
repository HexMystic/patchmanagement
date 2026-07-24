namespace PatchManagement.Connectors.Model;

/// <summary>
/// Describes a file transfer. For a <c>Push</c> the source is either <see cref="Content"/> or a
/// local file at <see cref="LocalPath"/>, written to <see cref="RemotePath"/>. For a <c>Pull</c>
/// the source is <see cref="RemotePath"/>; the bytes are returned in the result (and also written
/// to <see cref="LocalPath"/> when supplied).
///
/// Pushing the payload to the target first (then executing locally) is the recommended way to
/// avoid a WinRM double-hop entirely (HARD-PROBLEMS #9).
/// </summary>
public sealed record FileTransfer
{
    public required string RemotePath { get; init; }

    /// <summary>Local filesystem path (optional if <see cref="Content"/> is supplied for a push).</summary>
    public string? LocalPath { get; init; }

    /// <summary>In-memory content for a push (takes precedence over <see cref="LocalPath"/>).</summary>
    public ReadOnlyMemory<byte>? Content { get; init; }

    /// <summary>Explicit time budget for the transfer — no unbounded transfer (NEVER #5).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Optional idempotency key to serialise concurrent transfers of the same payload.</summary>
    public string? IdempotencyKey { get; init; }
}
