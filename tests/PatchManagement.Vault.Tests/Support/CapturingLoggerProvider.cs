using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// Captures every log line emitted through it — message plus the formatted state and any exception
/// text — so a test can scan the full body of what the vault logged and assert no secret material
/// ever appears (THREAT-MODEL "Never logged"). This is the scanner the threat model asks for.
/// </summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<string> Lines { get; } = new();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, Lines);

    public void Dispose() { }

    public string AllText => string.Join("\n", Lines);

    public ILogger<T> CreateLogger<T>() => new TypedLogger<T>(new CapturingLogger(typeof(T).FullName ?? "T", Lines));

    private sealed class CapturingLogger(string category, ConcurrentQueue<string> lines) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var line = $"[{logLevel}] {category} {formatter(state, exception)}";
            if (exception is not null) line += " EX:" + exception;
            lines.Enqueue(line);
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
