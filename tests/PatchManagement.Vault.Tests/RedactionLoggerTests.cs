using Microsoft.Extensions.Logging;
using PatchManagement.Vault.Logging;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Proves the defense-in-depth redaction filter: a registered sentinel is scrubbed from a formatted
/// log line before it reaches the sink, and unrelated text passes through untouched.
/// </summary>
public sealed class RedactionLoggerTests
{
    [Fact]
    public void Registered_secret_is_redacted_from_emitted_log_lines()
    {
        using var capturing = new CapturingLoggerProvider();
        var redacting = new SecretRedactingLoggerProvider(capturing);
        redacting.Register("TOPSECRET-value");

        var logger = redacting.CreateLogger("test");
        logger.LogInformation("leaking {Value} by accident", "TOPSECRET-value");

        var text = string.Join("\n", capturing.Lines);
        Assert.DoesNotContain("TOPSECRET-value", text);
        Assert.Contains(SecretRedactingLoggerProvider.Redacted, text);
    }

    [Fact]
    public void Non_secret_text_passes_through_unchanged()
    {
        using var capturing = new CapturingLoggerProvider();
        var redacting = new SecretRedactingLoggerProvider(capturing);
        redacting.Register("some-secret");

        var logger = redacting.CreateLogger("test");
        logger.LogInformation("ordinary metadata message");

        Assert.Contains("ordinary metadata message", string.Join("\n", capturing.Lines));
    }

    /// <summary>
    /// The exception OBJECT is a leak channel in its own right: sinks render
    /// <c>exception.ToString()</c>, which carries message and stack. A sentinel in either must be
    /// scrubbed before the sink sees it. The stack is seeded explicitly because a genuine stack
    /// trace holds method names, not values — the property under test is that the stack TEXT is
    /// filtered, whatever put a secret there.
    /// </summary>
    [Fact]
    public void Secret_in_exception_message_and_stack_is_scrubbed_before_the_sink()
    {
        const string secret = "TOPSECRET-in-exception";
        using var capturing = new CapturingLoggerProvider();
        var redacting = new SecretRedactingLoggerProvider(capturing);
        redacting.Register(secret);

        var thrown = new StackSeededException(
            $"connect failed for password={secret}",
            $"   at Vault.Connect(String pw = \"{secret}\")");

        redacting.CreateLogger("test").LogError(thrown, "vault operation failed");

        var text = capturing.AllText;
        Assert.DoesNotContain(secret, text);
        Assert.Contains(SecretRedactingLoggerProvider.Redacted, text);
        Assert.Contains("vault operation failed", text);        // the non-secret line survives
        Assert.Contains(nameof(StackSeededException), text);    // type kept, so diagnosis survives
    }

    /// <summary>
    /// InnerException and Data are dropped rather than forwarded, because neither can be scrubbed in
    /// general. Asserted against the stand-in object, not the captured text: those two channels are
    /// rendered by structured sinks rather than by ToString(), so a text-only assertion would pass
    /// vacuously and prove nothing.
    /// </summary>
    [Fact]
    public void Inner_exception_and_data_are_dropped_rather_than_forwarded()
    {
        const string secret = "TOPSECRET-nested";
        using var capturing = new CapturingLoggerProvider();
        var redacting = new SecretRedactingLoggerProvider(capturing);
        redacting.Register(secret);

        var inner = new InvalidOperationException($"unwrap failed with key {secret}");
        var outer = new InvalidOperationException("resolve failed", inner);
        outer.Data["dek"] = secret;

        var redacted = redacting.ScrubException(outer);

        Assert.NotNull(redacted);
        Assert.Null(redacted!.InnerException);
        Assert.Empty(redacted.Data);
        Assert.DoesNotContain(secret, redacted.ToString());

        // And end-to-end: nothing reaching the sink carries the nested secret either.
        redacting.CreateLogger("test").LogError(outer, "resolve failed");
        Assert.DoesNotContain(secret, capturing.AllText);
    }

    /// <summary>Exception with a caller-supplied stack trace, so the stack-scrubbing path is
    /// reachable from a test at all.</summary>
    private sealed class StackSeededException(string message, string stack) : Exception(message)
    {
        public override string? StackTrace { get; } = stack;
    }
}
