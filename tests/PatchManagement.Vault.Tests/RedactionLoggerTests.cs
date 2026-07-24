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
}
