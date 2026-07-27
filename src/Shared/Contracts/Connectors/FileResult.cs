namespace PatchManagement.Contracts.Connectors;

/// <summary>Typed result of a push/pull. Failure is modelled, not thrown.</summary>
public sealed record FileResult
{
    public required ConnectorOutcome Outcome { get; init; }
    public string RemotePath { get; init; } = string.Empty;
    public long BytesTransferred { get; init; }

    /// <summary>For a pull: the retrieved bytes. Never populated for a push.</summary>
    public ReadOnlyMemory<byte>? Content { get; init; }

    public TimeSpan Duration { get; init; }
    public string? Detail { get; init; }

    public bool Succeeded => Outcome == ConnectorOutcome.Ok;

    public static FileResult Ok(string remotePath, long bytes, TimeSpan duration, ReadOnlyMemory<byte>? content = null) => new()
    {
        Outcome = ConnectorOutcome.Ok,
        RemotePath = remotePath,
        BytesTransferred = bytes,
        Duration = duration,
        Content = content,
    };

    public static FileResult Failed(ConnectorOutcome outcome, string remotePath, string detail, TimeSpan duration) => new()
    {
        Outcome = outcome,
        RemotePath = remotePath,
        Detail = detail,
        Duration = duration,
    };
}
