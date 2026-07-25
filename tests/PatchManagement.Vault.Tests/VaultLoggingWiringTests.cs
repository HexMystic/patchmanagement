using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PatchManagement.Vault.Logging;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// The belt has to be ON, not merely correct when called directly. These build a container the way
/// the host does — a sink registered, then AddVaultModule — and assert through the ordinary
/// ILogger&lt;T&gt; resolution path, so a regression that leaves the provider unregistered fails here
/// even though every direct-call test in RedactionLoggerTests still passes.
/// </summary>
public sealed class VaultLoggingWiringTests
{
    [Fact]
    public void Vault_module_puts_the_redaction_belt_in_the_logging_pipeline()
    {
        const string secret = "TOPSECRET-wired";
        using var capturing = new CapturingLoggerProvider();

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(capturing));
        services.AddVaultModule(new ConfigurationBuilder().Build());

        using var sp = services.BuildServiceProvider();

        // Registered, and wrapping the sink that was already there.
        var belt = Assert.Single(sp.GetServices<ILoggerProvider>().OfType<SecretRedactingLoggerProvider>());
        belt.Register(secret);

        // Resolved the ordinary way, not hand-constructed.
        var logger = sp.GetRequiredService<ILogger<VaultCredentialProvider>>();
        logger.LogError(new InvalidOperationException($"unwrap failed: {secret}"), "vault op failed {Value}", secret);

        var text = capturing.AllText;
        Assert.NotEqual(string.Empty, text);
        Assert.DoesNotContain(secret, text);                            // message AND exception scrubbed
        Assert.Contains(SecretRedactingLoggerProvider.Redacted, text);
        Assert.Contains(RedactedException.RedactionNote, text);         // exception path is live too

        // Control, and the point of the test: the SAME sink in the SAME container records the SAME
        // secret verbatim when the log does not go through the belt. So the absence above is the belt
        // redacting in the live pipeline — not a sink that quietly drops text, and not an assertion
        // that would pass just because the provider object exists in the service collection.
        sp.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Some.Other.Component")
            .LogInformation("control {Value}", secret);

        Assert.Contains(secret, capturing.AllText);
    }

    [Fact]
    public void Unrelated_categories_keep_the_exception_detail_operators_diagnose_from()
    {
        using var capturing = new CapturingLoggerProvider();

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(capturing));
        services.AddVaultModule(new ConfigurationBuilder().Build());
        using var sp = services.BuildServiceProvider();

        var logger = sp.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Microsoft.EntityFrameworkCore.Database.Command");
        logger.LogError(
            new InvalidOperationException("outer", new InvalidOperationException("the root cause")),
            "db command failed");

        // The belt is category-scoped, so non-vault logging keeps its inner chain.
        Assert.Contains("the root cause", capturing.AllText);
        Assert.DoesNotContain(RedactedException.RedactionNote, capturing.AllText);
    }

    [Fact]
    public void Wiring_is_idempotent_when_the_module_is_added_twice()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(new CapturingLoggerProvider()));
        services.AddVaultModule(new ConfigurationBuilder().Build());
        services.AddVaultModule(new ConfigurationBuilder().Build());

        using var sp = services.BuildServiceProvider();

        // Double-wrapping would scrub twice and double-dispose the inner provider.
        Assert.Single(sp.GetServices<ILoggerProvider>().OfType<SecretRedactingLoggerProvider>());
    }
}
