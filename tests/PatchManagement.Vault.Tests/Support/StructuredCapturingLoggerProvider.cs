using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// Records what a STRUCTURED sink sees — the raw state values — as distinct from the formatted
/// message that <see cref="CapturingLoggerProvider"/> records.
///
/// <para>This exists because the two channels are genuinely different: a JSON console, an OTel
/// exporter, or <c>EventSourceLoggerProvider</c> enumerates <c>TState</c> as key/value pairs and
/// emits the raw values, and may never call the formatter at all. A harness that only records
/// <c>formatter(state, exception)</c> is blind to exactly the channel the redaction belt does not
/// cover (ADR 0012).</para>
///
/// <para><see cref="RenderedValues"/> renders each value the way a structured sink would rather than
/// via <c>string.Format</c> — notably a <c>byte[]</c> becomes base64, not "System.Byte[]" — so a
/// secret-sweep over it is meaningful.</para>
/// </summary>
public sealed class StructuredCapturingLoggerProvider : ILoggerProvider
{
    /// <summary>The formatted message channel — what <c>string.Format</c> substitution produces.</summary>
    public ConcurrentQueue<string> FormattedLines { get; } = new();

    /// <summary>The structured channel — the raw values a structured sink serializes.</summary>
    public ConcurrentQueue<KeyValuePair<string, object?>> StateValues { get; } = new();

    /// <summary>Exceptions as the sink received them, for asserting what the belt forwarded.</summary>
    public ConcurrentQueue<Exception> Exceptions { get; } = new();

    public string AllFormatted => string.Join("\n", FormattedLines);

    /// <summary>Every structured value, rendered as a structured sink would render it.</summary>
    public string AllRenderedValues =>
        string.Join("\n", StateValues.Select(kv => $"{kv.Key}={Render(kv.Value)}"));

    public ILogger CreateLogger(string categoryName) => new StructuredCapturingLogger(this);

    public ILogger<T> CreateLogger<T>() => new TypedLogger<T>(new StructuredCapturingLogger(this));

    public void Dispose() { }

    private static string Render(object? value) => value switch
    {
        null => "<null>",
        string s => s,
        byte[] bytes => Convert.ToBase64String(bytes), // what a JSON/OTel sink does, not "System.Byte[]"
        _ => value.ToString() ?? string.Empty,
    };

    private sealed class StructuredCapturingLogger(StructuredCapturingLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            owner.FormattedLines.Enqueue(formatter(state, exception));

            // The structured read: exactly what a JSON/OTel/EventSource sink enumerates.
            if (state is IReadOnlyList<KeyValuePair<string, object?>> pairs)
            {
                foreach (var pair in pairs) owner.StateValues.Enqueue(pair);
            }
            else if (state is not null)
            {
                owner.StateValues.Enqueue(new KeyValuePair<string, object?>("<state>", state));
            }

            if (exception is not null) owner.Exceptions.Enqueue(exception);
        }
    }

    private sealed class TypedLogger<T>(ILogger inner) : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => inner.BeginScope(state);
        public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => inner.Log(logLevel, eventId, state, exception, formatter);
    }
}
