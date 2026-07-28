using System.Text;

namespace PatchManagement.Contracts.Connectors;

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

    /// <summary>
    /// Keeps the payload out of the generated <c>ToString()</c>, printing its size instead.
    ///
    /// <para><see cref="ReadOnlyMemory{T}"/> happens to render as a type name today rather than as
    /// bytes, so this is not fixing a live leak. It is making the guarantee structural: a payload
    /// being pushed to an endpoint may well be a config file or a key bundle, and whether it stays
    /// out of a log should not depend on an implementation detail of how the BCL formats a struct.
    /// The byte count is the part a reader actually wants.</para>
    ///
    /// <para>Paths are kept: they are operationally essential and are not secrets.</para>
    /// </summary>
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("RemotePath = ").Append(RemotePath);
        builder.Append(", LocalPath = ").Append(LocalPath ?? "<none>");
        builder.Append(", Content = ")
               .Append(Content is { } c ? $"<{c.Length} bytes>" : "<none>");
        builder.Append(", Timeout = ").Append(Timeout);
        builder.Append(", IdempotencyKey = ").Append(IdempotencyKey ?? "<none>");
        return true;
    }
}
