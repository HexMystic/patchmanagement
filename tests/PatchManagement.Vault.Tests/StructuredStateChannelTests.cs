using System.Text;
using Microsoft.Extensions.Logging;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Logging;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Review finding H3. The redaction belt forwards STRUCTURED log state verbatim — the key/value
/// pairs a JSON console, an OTel exporter, or <c>EventSourceLoggerProvider</c> serializes, and which
/// such a sink may emit without ever calling the formatter.
///
/// <para>That channel stays uncovered by deliberate decision (ADR 0012 decision D): the belt scrubs
/// registered sentinels, nothing registers one at runtime, so a state scrubber built on it would be
/// inert — and type-based filtering would have to redact every string to be meaningful. What
/// protects this channel is the PRIMARY guarantee: vault code never puts secret material into a
/// log. These tests pin both halves — the boundary, so it cannot move silently, and the guarantee,
/// so it cannot rot.</para>
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class StructuredStateChannelTests(PostgresFixture fx)
{
    private readonly Guid Tenant = Guid.NewGuid();

    /// <summary>
    /// The boundary as an executable fact. If someone later makes the belt scrub structured state,
    /// this fails — which is the point: the change would contradict ADR 0012 and must be a deliberate
    /// amendment rather than a silent one. The final assertion doubles as the control proving the
    /// sink can see this channel at all.
    /// </summary>
    [Fact]
    public void The_belt_scrubs_the_formatted_message_but_not_structured_state()
    {
        const string sentinel = "TOPSECRET-structured";
        using var sink = new StructuredCapturingLoggerProvider();
        var belt = new SecretRedactingLoggerProvider(sink);
        belt.Register(sentinel);

        belt.CreateLogger("test").LogInformation("resolve failed for {Password}", sentinel);

        // Covered: the formatted channel.
        Assert.DoesNotContain(sentinel, sink.AllFormatted);
        Assert.Contains(SecretRedactingLoggerProvider.Redacted, sink.AllFormatted);

        // NOT covered, by design: the structured channel a JSON/OTel/EventSource sink reads.
        Assert.Contains(sentinel, sink.AllRenderedValues);
    }

    /// <summary>
    /// The guarantee that actually protects the uncovered channel: a real store + resolve through
    /// the vault puts no secret into structured state, in any encoding a structured sink would emit.
    /// Note a <c>byte[]</c> is rendered as base64 here, not "System.Byte[]" — the formatter-shaped
    /// harness would miss exactly that.
    /// </summary>
    [Fact]
    public async Task Vault_code_puts_no_secret_into_the_structured_channel()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(Tenant, "T");

        var secret = Encoding.UTF8.GetBytes("STRUCTLOG-" + Guid.NewGuid().ToString("N"));
        using var sink = new StructuredCapturingLoggerProvider();

        await using (var db = harness.AppContext(Tenant))
        {
            var vault = harness.Provider(db, Tenant, sink.CreateLogger<VaultCredentialProvider>());
            var reference = await vault.StoreAsync(
                new StoreCredentialRequest("structured", CredentialKind.WindowsPassword, secret, "domain-admin"),
                CancellationToken.None);
            using var _ = await vault.ResolveAsync(reference, CancellationToken.None);
        }

        var body = sink.AllRenderedValues;
        Assert.NotEqual(string.Empty, body); // sanity: structured values WERE captured

        Assert.DoesNotContain(Encoding.UTF8.GetString(secret), body);
        Assert.DoesNotContain(Convert.ToBase64String(secret), body);
        Assert.DoesNotContain(Convert.ToHexString(secret), body);
        Assert.DoesNotContain(Convert.ToHexString(secret).ToLowerInvariant(), body);
    }

    /// <summary>
    /// The belt replaces the exception only when armed. Unarmed — which is every production process,
    /// since nothing registers a sentinel — the original passes through, so an operator keeps the
    /// inner chain and Data instead of losing them for redaction that cannot fire.
    /// </summary>
    [Fact]
    public void The_exception_is_replaced_only_when_the_belt_is_armed()
    {
        var original = new InvalidOperationException("resolve failed", new InvalidOperationException("root cause"));

        using var unarmedSink = new StructuredCapturingLoggerProvider();
        var unarmed = new SecretRedactingLoggerProvider(unarmedSink);
        Assert.False(unarmed.IsArmed);
        unarmed.CreateLogger("test").LogError(original, "failed");

        Assert.Same(original, Assert.Single(unarmedSink.Exceptions));

        using var armedSink = new StructuredCapturingLoggerProvider();
        var armed = new SecretRedactingLoggerProvider(armedSink);
        armed.Register("TOPSECRET-armed");
        Assert.True(armed.IsArmed);
        armed.CreateLogger("test").LogError(original, "failed");

        Assert.IsType<RedactedException>(Assert.Single(armedSink.Exceptions));
    }
}
