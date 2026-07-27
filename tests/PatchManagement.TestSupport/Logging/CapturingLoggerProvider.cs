using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace PatchManagement.TestSupport.Logging;

/// <summary>
/// Records everything a real sink could see, keeping the channels separate.
///
/// <para>The channels are genuinely different, and that difference is the whole point. A JSON
/// console, an OTel exporter or <c>EventSourceLoggerProvider</c> enumerates <c>TState</c> as
/// key/value pairs and emits the <b>raw</b> values — it may never call the formatter at all. A
/// harness that records only <c>formatter(state, exception)</c> is blind to exactly the channel the
/// vault's redaction belt does not cover (ADR 0012 decision D). So a sweep that passes on the
/// formatted text alone has proven very little.</para>
///
/// <para>The Vault suite carries two providers for this — a formatter-shaped one and a structured
/// one, the second added later under review finding H4. One provider exposing both channels has the
/// same reach with less to keep in step, and can additionally record the <b>category</b>, which the
/// belt uses to decide coverage and which a wiring control test needs to assert on.</para>
/// </summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    /// <summary>The formatted-message channel — what <c>string.Format</c> substitution produced.</summary>
    public ConcurrentQueue<string> FormattedLines { get; } = new();

    /// <summary>The structured channel — the raw values a structured sink serializes.</summary>
    public ConcurrentQueue<KeyValuePair<string, object?>> StateValues { get; } = new();

    /// <summary>Exceptions exactly as the sink received them (i.e. after any belt substitution).</summary>
    public ConcurrentQueue<Exception> Exceptions { get; } = new();

    /// <summary>Category of every record, so a test can prove which categories were covered.</summary>
    public ConcurrentQueue<string> Categories { get; } = new();

    public string AllFormatted => string.Join("\n", FormattedLines);

    /// <summary>Every structured value, rendered the way a structured sink would render it.</summary>
    public string AllRenderedValues =>
        string.Join("\n", StateValues.Select(kv => $"{kv.Key}={Render(kv.Value)}"));

    /// <summary>Exception text, for error-path sweeps where the throw itself is the risk.</summary>
    public string AllExceptionText => string.Join("\n", Exceptions.Select(e => e.ToString()));

    /// <summary>
    /// Every channel at once. Use for a belt-and-braces sweep; prefer the per-channel properties
    /// when a test needs to say <em>which</em> channel leaked.
    /// </summary>
    public string Everything => string.Join("\n", AllFormatted, AllRenderedValues, AllExceptionText);

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);

    /// <summary>Typed logger, so this can be injected where a component wants <c>ILogger&lt;T&gt;</c>.</summary>
    public ILogger<T> CreateLogger<T>() =>
        new TypedLogger<T>(new CapturingLogger(this, typeof(T).FullName ?? typeof(T).Name));

    public void Dispose() { }

    private static string Render(object? value) => value switch
    {
        null => "<null>",
        string s => s,
        // What a JSON/OTel sink does. string.Format would render "System.Byte[]" and hide the secret.
        byte[] bytes => Convert.ToBase64String(bytes),
        _ => value.ToString() ?? string.Empty,
    };

    private sealed class CapturingLogger(CapturingLoggerProvider owner, string category) : ILogger
    {
        // Returns null deliberately: scope state is a channel the belt does not scrub either, and a
        // harness that swallowed scopes silently would hide that. Connector code is forbidden from
        // using BeginScope at all, which a convention test enforces rather than this class.
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            owner.Categories.Enqueue(category);
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
