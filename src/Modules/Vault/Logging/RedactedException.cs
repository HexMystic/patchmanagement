namespace PatchManagement.Vault.Logging;

/// <summary>
/// A log-safe stand-in for an exception that is about to reach a logging sink.
///
/// <para>A raw <see cref="Exception"/> is unsafe to hand to a sink under NEVER #1 for two different
/// reasons. Its <see cref="Exception.Message"/> and <see cref="Exception.StackTrace"/> are free text
/// a future caller could interpolate a secret into — those can be scrubbed. Its
/// <see cref="Exception.InnerException"/> and <see cref="Exception.Data"/> cannot: Data holds
/// arbitrary boxed objects with no string to filter, and an inner chain repeats the whole problem at
/// every level down. Structured sinks render both.</para>
///
/// <para>So message and stack are scrubbed and carried across, and the two unscrubbable channels are
/// dropped BY CONSTRUCTION: this is a new exception, so <see cref="Exception.InnerException"/> is
/// null and <see cref="Exception.Data"/> is empty because nothing is ever copied into them.</para>
///
/// <para>The original type name is preserved — a compile-time constant, never secret-bearing — and
/// <see cref="ToString"/> says plainly that redaction happened, so an operator reading a log does
/// not mistake a dropped inner chain for "there wasn't one".</para>
/// </summary>
public sealed class RedactedException(string message, string? stackTrace, string originalTypeName)
    : Exception(message)
{
    /// <summary>Marker in <see cref="ToString"/> so a log reader knows this is not the raw exception.</summary>
    public const string RedactionNote =
        "redacted by SecretRedactingLoggerProvider; InnerException and Data dropped";

    /// <summary>Type of the exception this stands in for, kept for diagnosis.</summary>
    public string OriginalTypeName { get; } = originalTypeName;

    /// <inheritdoc />
    public override string? StackTrace { get; } = stackTrace;

    /// <inheritdoc />
    public override string ToString()
    {
        var text = $"{OriginalTypeName}: {Message} [{RedactionNote}]";
        return StackTrace is { Length: > 0 } stack ? text + Environment.NewLine + stack : text;
    }
}
