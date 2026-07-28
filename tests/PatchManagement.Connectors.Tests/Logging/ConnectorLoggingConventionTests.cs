using System.Text.RegularExpressions;
using PatchManagement.Connectors.Ssh;
using PatchManagement.Contracts.Connectors;
using PatchManagement.TestSupport;
using PatchManagement.TestSupport.Conventions;

namespace PatchManagement.Connectors.Tests.Logging;

/// <summary>
/// The NeverLog scan, extended to the connector module. ADR 0012 hands Phase 3 this obligation
/// verbatim: "Phase 3 must extend the NeverLog scan to its own module; the vault-scoped belt does
/// not cover connector log categories."
///
/// <para>Note what that asks for and what it does not. It asks for the SCAN. It does not ask for the
/// belt to be widened, and widening it would be ceremony: ADR 0012 decision A rejects resolve-time
/// secret self-registration, so nothing arms the belt in production and it is inert by design.
/// Adding connector categories would buy zero protection while stripping InnerException and Data
/// from connector diagnostics. The connector's guarantee is stronger and simpler — it never hands
/// secret material to a logger at all — and that is what these assert.</para>
/// </summary>
public sealed class ConnectorLoggingConventionTests
{
    private static readonly string[] ScannedDirectories =
    [
        RepoPaths.Source("src", "Modules", "Connectors"),
        RepoPaths.Source("src", "Shared", "Contracts", "Connectors"),
    ];

    // ---------------------------------------------------------------------------------------
    // Patterns.
    //
    // ANCHOR DISCIPLINE. None of these places \b next to a non-word character. A word boundary sits
    // BETWEEN a word and a non-word character, so \b immediately before "-" or "." fails whenever
    // the preceding character is also non-word — which is how this module's own double-hop detector
    // matched "\b-ComputerName" and could never fire on " -ComputerName". A convention scan with a
    // broken anchor is green and guards nothing, which is precisely the failure ADR 0012 exists to
    // prevent. Every pattern below is exercised against a known-offending sample by
    // Every_scan_pattern_matches_the_offence_it_is_meant_to_catch.
    // ---------------------------------------------------------------------------------------

    /// <summary>Any use of logging scopes. Word-char delimited, so no \b is needed at all.</summary>
    private static readonly Regex BeginScopeUse = new(@"BeginScope", RegexOptions.CultureInvariant);

    /// <summary>
    /// An exception constructed from remote output. Scoped to the statement with <c>[^;]*</c> rather
    /// than <c>[^)]*</c>, because the offending form nests parentheses:
    /// <c>new X(Outcome.Y, "msg: " + (result.Detail ?? result.StandardError));</c>
    /// </summary>
    private static readonly Regex ExceptionFromRemoteOutput = new(
        @"new\s+\w*Exception\s*\([^;]*(StandardError|StandardOutput|StdErr|StdOut)",
        RegexOptions.CultureInvariant);

    /// <summary>Member names that could carry a secret. Substring, case-insensitive, unanchored.</summary>
    private static readonly Regex SecretVocabulary = new(
        "secret|password|passphrase|plaintext|credential|commandline|stdin|payload",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// A logging call whose ARGUMENTS reference secret material.
    ///
    /// <para>Cold review R2 finding #4: the scans in this file checked scopes, exception construction
    /// and record shapes — none of which match the most obvious leak of all, handing a resolved secret
    /// straight to a logger. The reviewer proved it by planting
    /// <c>_logger.LogWarning("...{Secret}", credential.Secret.ToArray())</c> in <c>WinRmConnector</c>;
    /// the entire suite stayed green.</para>
    ///
    /// <para>Matched over the FULL FILE TEXT with <c>Singleline</c>, not line by line, because a
    /// logging call wide enough to carry a secret is exactly the kind a formatter wraps. Scoped to the
    /// statement with <c>[^;]*</c> so it cannot run past the call it is describing.</para>
    /// </summary>
    private static readonly Regex SecretHandedToLogger = new(
        @"Log(?:Trace|Debug|Information|Warning|Error|Critical)\s*\([^;]*"
        + @"(?:\.Secret\b|SecurePassword|PrivateKeyBytes|[Pp]laintext|\.Password\b)",
        RegexOptions.Singleline | RegexOptions.CultureInvariant);

    /// <summary>
    /// Any write to console/debug/trace from production connector code.
    ///
    /// <para>These bypass the logging pipeline completely — no category, no level, no redaction, and
    /// invisible to every sweep in <c>ConnectorNeverLogTests</c>, which can only observe what reaches
    /// an <c>ILogger</c>. The reviewer's second plant was exactly this shape
    /// (<c>Console.WriteLine(Convert.ToBase64String(credential.Secret))</c>) and no behavioural test
    /// could ever have caught it. A module that never writes to them at all is a much easier rule to
    /// enforce than one that writes to them carefully.</para>
    /// </summary>
    private static readonly Regex ConsoleOrDebugWrite = new(
        @"(?<![\w.])(?:Console|Debug|Trace)\s*\.\s*(?:Write|WriteLine|Print|Fail)\s*\(",
        RegexOptions.CultureInvariant);

    [Fact]
    public void The_connector_module_creates_no_logging_scopes()
    {
        var hits = ScannedDirectories.SelectMany(d => SourceScanner.Scan(d, BeginScopeUse)).ToList();

        Assert.True(
            hits.Count == 0,
            "Connector code uses a logging scope. Scope state is forwarded to sinks VERBATIM and is "
            + "explicitly uncovered by the redaction belt (ADR 0012 decision B), so anything placed "
            + $"in a scope reaches production sinks unscrubbed:{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));
    }

    [Fact]
    public void No_exception_message_is_built_from_remote_output()
    {
        var hits = ScannedDirectories.SelectMany(d => SourceScanner.Scan(d, ExceptionFromRemoteOutput)).ToList();

        Assert.True(
            hits.Count == 0,
            "An exception message is built from remote output. That message becomes Result.Detail, a "
            + "caller logs it, and remote stderr is arbitrary endpoint-chosen text that routinely "
            + $"quotes back the failing command. Use a ConnectorReason code:{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));
    }

    [Fact]
    public void No_logging_call_is_handed_secret_material()
    {
        var hits = ScannedDirectories.SelectMany(d => SourceScanner.ScanText(d, SecretHandedToLogger)).ToList();

        Assert.True(
            hits.Count == 0,
            "A logging call is being handed secret material. It reaches every configured sink, and the "
            + "structured channel renders a byte[] as base64 rather than hiding it behind "
            + $"\"System.Byte[]\" (NEVER #1, ADR 0012 decision D):{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));
    }

    [Fact]
    public void The_connector_module_never_writes_to_console_debug_or_trace()
    {
        var hits = ScannedDirectories.SelectMany(d => SourceScanner.ScanText(d, ConsoleOrDebugWrite)).ToList();

        Assert.True(
            hits.Count == 0,
            "Connector code writes to console/debug/trace. Those bypass the logging pipeline entirely — "
            + "no category, no level, no redaction — and are invisible to every never-log sweep, which "
            + $"can only observe what reaches an ILogger:{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));
    }

    [Fact]
    public void No_secret_shaped_record_relies_on_a_generated_ToString()
    {
        // Types with a hand-written redacting ToString/PrintMembers, each proven by a behavioural
        // test below rather than trusted because it appears in this list.
        Type[] covered = [typeof(RemoteCommand), typeof(FileTransfer)];

        var uncovered = RecordShapeScanner.Uncovered(
            [typeof(SshConnector).Assembly, typeof(IEndpointConnector).Assembly],
            SecretVocabulary,
            covered);

        Assert.True(
            uncovered.Count == 0,
            "These records carry a secret-shaped member and print it from a compiler-generated "
            + $"ToString(), so logging the record leaks it (ADR 0012 decision C):{Environment.NewLine}"
            + string.Join(Environment.NewLine, uncovered.Select(t => RecordShapeScanner.Describe(t, SecretVocabulary))));
    }

    [Fact]
    public void A_command_line_does_not_appear_in_the_records_own_ToString()
    {
        var rendered = new RemoteCommand { CommandLine = "curl -u admin:hunter2 https://x" }.ToString();

        Assert.DoesNotContain("hunter2", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("curl", rendered, StringComparison.Ordinal);
        Assert.Contains("redacted", rendered, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_transfer_payload_does_not_appear_in_the_records_own_ToString()
    {
        var rendered = new FileTransfer
        {
            RemotePath = "/tmp/x.bin",
            Content = "SENTINEL-PAYLOAD"u8.ToArray(),
        }.ToString();

        Assert.DoesNotContain("SENTINEL", rendered, StringComparison.Ordinal);
        Assert.Contains("/tmp/x.bin", rendered, StringComparison.Ordinal); // paths are not secrets
    }

    /// <summary>
    /// The anchor audit, as an executable test.
    ///
    /// <para>A convention scan that cannot match its target passes forever and guards nothing. This
    /// module already shipped one — <c>\b-ComputerName\b</c> in the double-hop detector, inert
    /// because a word boundary cannot sit between a space and a hyphen. So every pattern above is
    /// checked against a sample it MUST match and one it must NOT, and a broken anchor fails here
    /// immediately rather than silently disarming a guard.</para>
    /// </summary>
    [Fact]
    public void Every_scan_pattern_matches_the_offence_it_is_meant_to_catch()
    {
        // BeginScope: with and without leading whitespace, and as a member access.
        Assert.Matches(BeginScopeUse, "using var s = _logger.BeginScope(new { Foo = 1 });");
        Assert.Matches(BeginScopeUse, "BeginScope(state)");
        Assert.DoesNotMatch(BeginScopeUse, "// scopes are not used in this module");

        // The exact statement shape this module actually had, nested parentheses and all.
        Assert.Matches(
            ExceptionFromRemoteOutput,
            @"throw new ConnectorConnectException(ConnectorOutcome.ProtocolError, ""WinRM upload failed: "" + (result.Detail ?? result.StandardError));");
        Assert.Matches(
            ExceptionFromRemoteOutput,
            @"throw new FactsCollectionException($""failed: {result.StandardOutput}"");");

        // ...and it must not fire on merely returning remote output, which is legitimate: the
        // caller's payload is not the module's diagnostic.
        Assert.DoesNotMatch(
            ExceptionFromRemoteOutput,
            "return CommandResult.Ran(exitCode, stdout.ToString(), stderr.ToString(), sw.Elapsed);");

        // ---- The two rules added by cold review R2 finding #4, against the reviewer's ACTUAL plants.

        // Plant 1, verbatim. The whole suite stayed green with this in WinRmConnector.RunAsync.
        Assert.Matches(
            SecretHandedToLogger,
            @"_logger.LogWarning(""winrm auth material {Secret}"", credential.Secret.ToArray());");

        // ...and wrapped across lines, which is how it would really be written once the argument list
        // grows. A line-scoped scan misses this entirely — hence SourceScanner.ScanText.
        Assert.Matches(
            SecretHandedToLogger,
            """
            _logger.LogWarning(
                "winrm auth material {Secret}",
                credential.Secret.ToArray());
            """);

        // Plant 2, verbatim: no logger involved, so no behavioural sweep could ever see it.
        Assert.Matches(
            ConsoleOrDebugWrite,
            @"Console.WriteLine(""ssh key material {0}"", Convert.ToBase64String(credential.Secret));");
        Assert.Matches(ConsoleOrDebugWrite, "Debug.WriteLine(secret);");
        Assert.Matches(ConsoleOrDebugWrite, "Trace.Write(key);");

        // ...and neither may fire on the legitimate diagnostics this module actually contains, or the
        // rule gets suppressed rather than obeyed.
        Assert.DoesNotMatch(
            SecretHandedToLogger,
            @"_logger.LogInformation(""Connectivity probe to {Asset} failed: {Outcome}"", target.AssetId ?? target.Host, ex.Outcome);");
        Assert.DoesNotMatch(
            SecretHandedToLogger,
            @"_logger.LogError(ex, ""SSH transport fault contained during {Operation} on {Asset}."", operation, target.AssetId);");
        Assert.DoesNotMatch(ConsoleOrDebugWrite, "await destination.WriteAsync(bytes, ct);");
        Assert.DoesNotMatch(ConsoleOrDebugWrite, "await input.WriteAsync(stdin, cts.Token);");

        // Vocabulary: matches the member names it is for, in any casing.
        foreach (var name in new[] { "Secret", "password", "Passphrase", "CommandLine", "Stdin", "Payload" })
            Assert.Matches(SecretVocabulary, name);

        // ...and not the ones deliberately left out. "Key" and "Token" would match KeyId, ConnectionKey
        // and CancellationToken and drown the signal — the same narrowing the vault's scan documents.
        foreach (var name in new[] { "KeyId", "CancellationToken", "Host", "Port" })
            Assert.DoesNotMatch(SecretVocabulary, name);
    }

    [Fact]
    public void The_scans_actually_read_the_module()
    {
        // A directory that has moved or been renamed makes every scan above pass while reading
        // nothing at all — the failure mode that makes a green convention suite worthless.
        var files = ScannedDirectories.Sum(SourceScanner.FileCount);
        Assert.True(files > 20, $"the convention scans found only {files} source files to read");
    }
}
