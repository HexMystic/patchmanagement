using System.Text.RegularExpressions;
using PatchManagement.TestSupport;
using PatchManagement.TestSupport.Conventions;

namespace PatchManagement.Connectors.Tests.Credentials;

/// <summary>
/// What connector code is allowed to turn secret material into.
///
/// <para><b>Cold review R2 finding #7.</b> <c>HttpWinRmClient</c> did
/// <c>Encoding.UTF8.GetString(credential.Secret)</c> and called the result transient. It is not: a
/// .NET string is immutable, so it cannot be zeroed, and it survives on the managed heap until some
/// later collection — visible in a process dump for that whole window, and possibly duplicated when
/// the GC compacts. Every other credential path in this codebase zeroes in place
/// (<c>CryptographicOperations.ZeroMemory</c>, <c>ResolvedCredential.Dispose</c>, <c>Array.Clear</c>
/// after parsing a key), and there is a behavioural test asserting the sudo stdin buffer is all zeros
/// once the command returns. That single path opted out while its comment asserted the opposite.</para>
///
/// <para>This is a scan rather than a behavioural test because the defect is <em>unobservable at
/// runtime</em>: a managed string that exists for a while and is then collected looks identical, from
/// the outside, to one that was never created. Only the source can say which happened.</para>
/// </summary>
public sealed class SecretMaterialConventionTests
{
    private static readonly string[] ScannedDirectories =
    [
        RepoPaths.Source("src", "Modules", "Connectors"),
        RepoPaths.Source("src", "Shared", "Contracts", "Connectors"),
    ];

    /// <summary>
    /// Decoding secret bytes into a managed <c>string</c>.
    ///
    /// <para>Matched over the full file text so a call wrapped across lines is still caught, and
    /// scoped with <c>[^;]*</c> so it cannot run past its own statement.</para>
    /// </summary>
    private static readonly Regex SecretDecodedToString = new(
        @"(?:Encoding\.\w+\.GetString|Convert\.ToBase64String|BitConverter\.ToString)\s*\([^;]*\.Secret\b",
        RegexOptions.Singleline | RegexOptions.CultureInvariant);

    [Fact]
    public void No_secret_is_decoded_into_a_managed_string()
    {
        var hits = ScannedDirectories.SelectMany(d => SourceScanner.ScanText(d, SecretDecodedToString)).ToList();

        Assert.True(
            hits.Count == 0,
            "Secret material is being decoded into a managed string. A string cannot be zeroed and "
            + "outlives every attempt to clean it up, so the credential stays readable in a process "
            + "dump long after the operation finished. Use SecureString, or work on the bytes "
            + $"directly and clear the buffer:{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));
    }

    /// <summary>
    /// The pattern audit. A scan that cannot match its target passes forever and guards nothing —
    /// this module has already shipped one such scan (the <c>-ComputerName</c> anchor), which is why
    /// every scan here carries a control.
    /// </summary>
    [Fact]
    public void The_scan_matches_the_offence_it_is_meant_to_catch()
    {
        // The exact line that shipped, and the wrapped form a formatter would produce.
        Assert.Matches(
            SecretDecodedToString,
            "Credentials = new NetworkCredential(credential.Username, Encoding.UTF8.GetString(credential.Secret)),");
        Assert.Matches(
            SecretDecodedToString,
            """
            var password = Encoding.UTF8.GetString(
                credential.Secret);
            """);

        // The reviewer's console plant decoded the key the same way before printing it.
        Assert.Matches(SecretDecodedToString, "Convert.ToBase64String(credential.Secret)");

        // ...and it must not fire on the legitimate byte-level handling the module actually does.
        Assert.DoesNotMatch(SecretDecodedToString, "var bytes = credential.Secret.ToArray();");
        Assert.DoesNotMatch(SecretDecodedToString, "credential.Secret.CopyTo(buffer);");
        Assert.DoesNotMatch(SecretDecodedToString, "return ToSecureString(credential.Secret);");
        Assert.DoesNotMatch(
            SecretDecodedToString, "var b64 = Convert.ToBase64String(content); // file payload, not a secret");
    }

    [Fact]
    public void The_scan_actually_reads_the_module()
    {
        var files = ScannedDirectories.Sum(SourceScanner.FileCount);
        Assert.True(files > 20, $"the secret-material scan found only {files} source files to read");
    }
}
