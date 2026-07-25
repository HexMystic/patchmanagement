using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace PatchManagement.Vault.Logging;

/// <summary>
/// Defense-in-depth redaction filter for the logging pipeline (THREAT-MODEL "Never logged").
///
/// The primary guarantee is that vault code simply never passes secret material to a logger — that
/// is proven by a test that runs the whole store/resolve/rotate flow and scans every emitted log
/// line for the secret. This provider is the belt to that suspenders: it wraps another
/// <see cref="ILoggerProvider"/> and scrubs any registered sentinel substring from the FORMATTED
/// message before it reaches the sink, so a stray future interpolation of a known-sensitive value
/// is caught rather than written.
///
/// It covers BOTH channels a sink renders: the formatted message, and the exception object — see
/// <see cref="RedactedException"/> for why the latter is replaced rather than filtered in place.
///
/// It scrubs by explicit registration (<see cref="Register"/>) rather than guessing, because the
/// only thing that can reliably be recognised as "this exact secret" is a value someone hands us —
/// e.g. a test proving the filter bites, or a caller who knows a literal must never surface.
/// </summary>
public sealed class SecretRedactingLoggerProvider(ILoggerProvider inner, Func<string, bool>? appliesTo = null)
    : ILoggerProvider, ISupportExternalScope
{
    public const string Redacted = "***REDACTED***";

    private readonly ConcurrentDictionary<string, byte> _sentinels = new(StringComparer.Ordinal);

    /// <summary>
    /// Register a literal that must never appear in a log line. Ignores empty/whitespace.
    ///
    /// <para>Takes literals that are ALREADY resident for the process lifetime — a config-sourced
    /// value, or a test proving the filter bites. Per-request resolved credentials are deliberately
    /// NOT registered: the argument is held as a non-zeroable string until the process exits, so
    /// registering each resolved secret would build a permanent plaintext registry and defeat the
    /// pinned-buffer zeroing it is meant to complement. Rejected, not deferred — see
    /// ADR 0012 (docs/adr/0012-log-redaction-scope.md).</para>
    /// </summary>
    public void Register(string secret)
    {
        if (!string.IsNullOrWhiteSpace(secret)) _sentinels.TryAdd(secret, 0);
    }

    public string Scrub(string message)
    {
        foreach (var sentinel in _sentinels.Keys)
        {
            if (message.Contains(sentinel, StringComparison.Ordinal))
                message = message.Replace(sentinel, Redacted, StringComparison.Ordinal);
        }
        return message;
    }

    /// <summary>
    /// Produces a log-safe stand-in for <paramref name="exception"/>: message and stack scrubbed,
    /// InnerException and Data dropped. Null in, null out. See <see cref="RedactedException"/>.
    /// </summary>
    public RedactedException? ScrubException(Exception? exception)
    {
        if (exception is null) return null;

        var type = exception.GetType();
        return new RedactedException(
            Scrub(exception.Message),
            exception.StackTrace is { } stack ? Scrub(stack) : null,
            type.FullName ?? type.Name);
    }

    /// <summary>
    /// Wraps the inner logger when <paramref name="categoryName"/> is in scope for redaction. With no
    /// predicate every category is wrapped; the host wiring passes one so the belt covers vault code
    /// without stripping exception detail from unrelated application logging.
    /// </summary>
    public ILogger CreateLogger(string categoryName) =>
        appliesTo is null || appliesTo(categoryName)
            ? new RedactingLogger(inner.CreateLogger(categoryName), this)
            : inner.CreateLogger(categoryName);

    /// <summary>
    /// Forwarded so wrapping a provider does not silently cost it scope support: LoggerFactory hands
    /// the external scope provider only to providers that implement this, and without the forward the
    /// inner provider would never receive it (console scopes would just stop appearing).
    /// </summary>
    public void SetScopeProvider(IExternalScopeProvider scopeProvider)
    {
        if (inner is ISupportExternalScope supported) supported.SetScopeProvider(scopeProvider);
    }

    public void Dispose() => inner.Dispose();

    private sealed class RedactingLogger(ILogger inner, SecretRedactingLoggerProvider owner) : ILogger
    {
        // Scope state is NOT scrubbed — it is forwarded to the sink exactly as given. TState is
        // arbitrary (commonly an anonymous type) and cannot be rewritten while preserving what a
        // structured sink reads from it. Accepted because nothing in the module creates a
        // data-carrying scope, and VaultLoggingConventionTests fails if that changes. Note the
        // capturing harness behind NeverLogTests discards scope state, so that suite cannot see
        // this channel — the convention test is the guard. ADR 0012.
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => inner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            // The sink gets the stand-in, never the original. Scrubbing only the formatted message
            // would leave the exception object — which sinks render via ToString(), and structured
            // sinks by walking Data and the inner chain — completely unfiltered.
            var redacted = owner.ScrubException(exception);

            inner.Log(logLevel, eventId, state, redacted,
                (s, e) => owner.Scrub(formatter(s, e)));
        }
    }
}
