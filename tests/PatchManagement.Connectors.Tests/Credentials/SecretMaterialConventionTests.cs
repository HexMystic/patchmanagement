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
/// <para>These are scans rather than behavioural tests because the defect is <em>unobservable at
/// runtime</em>: a managed string that exists for a while and is then collected looks identical, from
/// the outside, to one that was never created. Only the source can say which happened. Two behavioural
/// alternatives were built and measured before this was settled; both are red for correct code and one
/// is nondeterministic as well. See <b>docs/HARD-PROBLEMS.md §13</b> — read it before proposing a
/// third.</para>
///
/// <para><b>Layering, after cold review R4.</b>
/// <see cref="Every_route_from_bytes_to_managed_text_is_individually_justified"/> is the guarantee: it
/// enumerates every call that can make text from bytes and requires each to be justified, so a new one
/// is red whatever shape fed it. The two pattern checks either side of it are narrow, historical, and
/// carry nothing on their own — R4 walked past both. Do not read a green run of those two as the rule
/// holding.</para>
/// </summary>
public sealed class SecretMaterialConventionTests
{
    private static readonly string[] ScannedDirectories =
    [
        RepoPaths.Source("src", "Modules", "Connectors"),
        RepoPaths.Source("src", "Shared", "Contracts", "Connectors"),

        // Added by cold review R4. ResolvedCredential — the type that HOLDS the secret — lives here
        // and was outside every scan, so a ToPlaintext() on the credential itself would have been
        // invisible to all of them.
        RepoPaths.Source("src", "Shared", "Contracts", "Credentials"),
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

    /// <summary>
    /// The statement-scoped form only.
    ///
    /// <para><b>This test does not carry the guarantee its name suggests, and did not when it was
    /// written.</b> Cold review R3 showed the pattern is anchored on <c>.Secret</c> appearing inside
    /// the same statement as the call, so splitting the offence across two lines walks straight past
    /// it. The universal claim — no secret reaches a managed string by any route — belongs to
    /// <see cref="Every_route_from_bytes_to_managed_text_is_individually_justified"/>.
    /// This is kept beside it as a cheap, exact check on the one form that actually shipped, and
    /// because two independent checks failing together localises a regression faster than one.</para>
    ///
    /// <para><b>Corrected again by R4.</b> This used to point at
    /// <see cref="No_secret_flows_into_a_managed_string"/> as the holder of the universal claim. That
    /// was wrong for the same reason at one remove: flow analysis never taints a parameter, so an
    /// extracted helper defeats it too. Both patterns here are narrow checks on shapes that actually
    /// shipped; neither carries the guarantee.</para>
    /// </summary>
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

    /// <summary>
    /// The rule the statement-scoped pattern above only half-enforces, followed through locals.
    ///
    /// <para><b>Demoted by cold review R4 — this is a second layer, not the guarantee.</b> R4 walked
    /// past it with an extracted helper, <c>DecodeSecret(byte[] m) => Encoding.UTF8.GetString(m)</c>,
    /// because taint is seeded from assignments and a parameter is not an assignment. Lambdas, local
    /// functions, extension methods, <c>out</c> parameters and instance fields all do the same. The
    /// universal claim now belongs to
    /// <see cref="Every_route_from_bytes_to_managed_text_is_individually_justified"/>; what this still
    /// adds is the case that check cannot see — a secret reaching one of the four calls that ARE
    /// justified.</para>
    ///
    /// <para><b>Cold review R3.</b> The pattern anchors on <c>.Secret</c> appearing inside the same
    /// statement as the call, so splitting the offence across two lines —
    /// <c>var b = credential.Secret.ToArray();</c> then <c>Encoding.UTF8.GetString(b);</c> —
    /// reintroduced the immortal managed string with all 113 tests green. That is not a hypothetical
    /// refactor; it is what the code looks like the moment anyone extracts a variable.</para>
    ///
    /// <para><b>Why this is not a behavioural test, despite the defect being a credential one.</b> The
    /// review asked for one, and the obvious candidate does not work:
    /// <see cref="System.Net.NetworkCredential"/> reports a non-null, non-read-only
    /// <c>SecurePassword</c> of identical length whichever constructor built it, so
    /// <c>Assert.NotNull(SecurePassword)</c> passes for the defect exactly as it passes for the fix.
    /// That was measured, not assumed. The managed string is created BEFORE the credential exists, and
    /// a string that is created and later collected is indistinguishable at runtime from one that never
    /// existed — so no assertion downstream of the constructor can see it. The enforcement therefore
    /// has to read the source; what it must NOT do is depend on which syntactic form was used, which is
    /// the defect this replaces.</para>
    /// </summary>
    [Fact]
    public void No_secret_flows_into_a_managed_string()
    {
        var hits = ScannedDirectories.SelectMany(SecretFlowScanner.Scan).ToList();

        Assert.True(
            hits.Count == 0,
            "Secret material reaches a call that materialises a managed string — directly or through a "
            + "local. A string cannot be zeroed and survives until some later collection, which may also "
            + "copy it while compacting, so the credential stays readable in a process dump long after "
            + $"the operation finished. Work on the bytes and clear the buffer:{Environment.NewLine}"
            + string.Join(Environment.NewLine, hits));
    }

    /// <summary>
    /// The flow analysis, proven against the offence it exists to catch — in every shape, including the
    /// two-statement one that defeated its predecessor.
    /// </summary>
    [Fact]
    public void The_flow_scan_follows_the_secret_through_local_variables()
    {
        // The original single-statement offence still has to be caught.
        Assert.NotEmpty(SecretFlowScanner.Offences(
            "var h = new NetworkCredential(c.Username, Encoding.UTF8.GetString(credential.Secret));"));

        // The two-statement form — the R3 hole. This is the case that matters.
        Assert.NotEmpty(SecretFlowScanner.Offences(
            """
            var secretBytes = credential.Secret.ToArray();
            var password = Encoding.UTF8.GetString(secretBytes);
            """));

        // ...and laundered through several hops, which a one-step check would miss.
        Assert.NotEmpty(SecretFlowScanner.Offences(
            """
            var a = credential.Secret.ToArray();
            var b = a;
            var c = b;
            var leaked = Convert.ToBase64String(c);
            """));

        // A copy INTO a buffer taints the destination — the shape SshConnector uses for sudo stdin.
        Assert.NotEmpty(SecretFlowScanner.Offences(
            """
            var buffer = new byte[credential.Secret.Length + 1];
            credential.Secret.CopyTo(buffer);
            var leaked = Convert.ToBase64String(buffer);
            """));

        // ...and it must not fire on the legitimate byte-level handling the module actually does, or
        // the rule gets suppressed rather than obeyed.
        Assert.Empty(SecretFlowScanner.Offences("return ToSecureString(credential.Secret);"));
        Assert.Empty(SecretFlowScanner.Offences(
            """
            var bytes = credential.Secret.ToArray();
            using var stream = new MemoryStream(bytes, writable: false);
            return new PrivateKeyFile(stream);
            """));

        // The transfer payload is not a secret, and neither is a remote stream's own content.
        Assert.Empty(SecretFlowScanner.Offences(
            """
            var content = file.Content?.ToArray() ?? await File.ReadAllBytesAsync(file.LocalPath!, ct);
            var b64 = Convert.ToBase64String(content);
            """));
        Assert.Empty(SecretFlowScanner.Offences(
            "var text = Encoding.UTF8.GetString(Convert.FromBase64String(stream.Value));"));
    }

    /// <summary>
    /// Every call in the connector surface that can turn bytes or chars into managed text, with the
    /// reason it is allowed to exist. Adding a route is a deliberate act with a written justification,
    /// not a refactor nobody reviewed.
    ///
    /// <para>Keyed by file and call text, never by line number — see
    /// <see cref="SecretMaterialisationScanner.Site.Key"/> for why.</para>
    /// </summary>
    private static readonly Dictionary<string, string> JustifiedMaterialisations = new(StringComparer.Ordinal)
    {
        ["src/Modules/Connectors/WinRm/HttpWinRmClient.cs :: Encoding.UTF8.GetChars(utf8Secret, chars)"] =
            "ToSecureString. This one DOES touch the secret, deliberately: it is the conversion that "
            + "exists so the password never becomes a string. The chars go into a caller-owned buffer "
            + "wiped in a finally, and straight into a SecureString. Replacing it with GetString is the "
            + "original R2 finding #7.",

        ["src/Modules/Connectors/WinRm/HttpWinRmClient.cs :: Convert.ToBase64String(content)"] =
            "UploadAsync. 'content' is the file being transferred to the endpoint — a payload the caller "
            + "chose, never credential material. Base64 is the wire format for the PowerShell writer.",

        ["src/Modules/Connectors/WinRm/HttpWinRmClient.cs :: Encoding.UTF8.GetString(Convert.FromBase64String(stream.Value))"] =
            "AppendStreams. Decodes the REMOTE command's own stdout/stderr, which arrives base64 in the "
            + "WS-Man response. Data coming back from the endpoint, not a secret going to it.",

        ["src/Modules/Connectors/WinRm/HttpWinRmClient.cs :: Convert.ToBase64String(Encoding.Unicode.GetBytes(script))"] =
            "EncodePowerShell. Encodes the command text for -EncodedCommand. The input is a script we "
            + "built, and the direction is text to bytes to text — no secret is in it.",
    };

    /// <summary>
    /// <b>The primary guarantee for the no-plaintext-secret rule</b> (CLAUDE.md NEVER #1/#2, cold
    /// review R2 finding #7, enforcement model in HARD-PROBLEMS §13). Every route from bytes to managed text in the
    /// connector surface is enumerated and justified; a new one fails until someone writes down why.
    ///
    /// <para><b>Cold review R4 replaced flow analysis with this, and the reason matters.</b> R4 broke
    /// <see cref="SecretFlowScanner"/> by extracting a method:
    /// <c>DecodeSecret(byte[] m) => Encoding.UTF8.GetString(m)</c>, called with the secret, launders a
    /// private key into an immortal string with every test green — because taint is tracked through
    /// locals and a parameter is not a local. Lambdas, local functions, extension methods, <c>out</c>
    /// parameters, instance fields and cross-file helpers all walk past it the same way. Adding those
    /// shapes to the analysis loses by construction: whoever writes the laundering picks the shape
    /// afterwards.</para>
    ///
    /// <para>This check does not care about the shape. It does not track the bytes at all. Laundering
    /// them into a string has to call something that makes text, in code we own, and there are four
    /// such calls in the whole surface. The fifth is red no matter which helper, lambda or field fed
    /// it.</para>
    ///
    /// <para><b>Why not a behavioural test instead.</b> R4 asked for one. It was built and measured
    /// rather than argued about, and it does not work — in three independent ways, any one of which is
    /// disqualifying. Scanning this process's own writable memory for the secret as UTF-16 shows that
    /// (a) SSH.NET's key parser leaves <b>four</b> managed copies of every private key it reads;
    /// (b) reading <c>NetworkCredential.Password</c>, which any HTTP auth stack must do, creates
    /// another; and (c) even the CORRECT first-party path is not clean — <c>SecureString.AppendChar</c>
    /// decrypts to append, so <c>ToSecureString</c> was measured leaving up to three transient UTF-16
    /// copies, <b>nondeterministically</b>: one run in five showed four occurrences where the other
    /// four showed none. So the assertion is red for code that is right, red for third-party code we
    /// cannot change, and flaky on top. A test that fails intermittently on correct code does not
    /// enforce a guarantee, it erodes one. The numbers are in docs/HARD-PROBLEMS.md §13 so this is not
    /// re-proposed each review.</para>
    /// </summary>
    [Fact]
    public void Every_route_from_bytes_to_managed_text_is_individually_justified()
    {
        var sites = ScannedDirectories.SelectMany(SecretMaterialisationScanner.Sites).ToList();

        var unjustified = sites.Where(s => !JustifiedMaterialisations.ContainsKey(s.Key)).ToList();

        Assert.True(
            unjustified.Count == 0,
            "New route(s) from bytes to managed text in the connector surface. A managed string cannot "
            + "be zeroed and survives until some later collection, so if any of these can ever carry "
            + "credential material the secret stays readable in a process dump long after the operation "
            + "finished. Work on the bytes and clear the buffer; if the call genuinely cannot carry a "
            + "secret, add it to JustifiedMaterialisations with the reason:"
            + $"{Environment.NewLine}"
            + string.Join(
                Environment.NewLine,
                unjustified.Select(s => $"  {s.RelativePath}:{s.Line}  {s.Call}")));

        // An allow-list nobody prunes becomes a rubber stamp: entries for calls that no longer exist
        // are exactly the cover a reinstated call slips back in under.
        var stale = JustifiedMaterialisations.Keys
            .Where(key => sites.All(s => s.Key != key))
            .ToList();

        Assert.True(
            stale.Count == 0,
            "JustifiedMaterialisations has entries matching no call in the source. Delete them — a "
            + "stale allow-list silently re-permits whatever returns to that shape. The justification "
            + $"is reproduced so you can tell a rename from a removal:{Environment.NewLine}"
            + string.Join(
                Environment.NewLine,
                stale.Select(k => $"  {k}{Environment.NewLine}      was justified as: {JustifiedMaterialisations[k]}")));
    }

    /// <summary>
    /// The capability scan, proven against the exact laundering R4 built and against the shapes that
    /// defeated its predecessor — a scan that cannot match its target passes forever and guards
    /// nothing, which this module has now shipped three times.
    /// </summary>
    [Fact]
    public void The_capability_scan_catches_every_shape_that_defeated_flow_analysis()
    {
        // R4's exploit verbatim: a helper method, which flow analysis cannot taint.
        Assert.NotEmpty(SecretMaterialisationScanner.SitesIn(
            "private static string DecodeSecret(byte[] material) => Encoding.UTF8.GetString(material);"));

        // ...and every other shape that walked past SecretFlowScanner, all caught for the same reason:
        // the scan looks at the call, not at how the bytes reached it.
        Assert.NotEmpty(SecretMaterialisationScanner.SitesIn(
            "Func<byte[], string> decode = m => Encoding.UTF8.GetString(m);"));
        Assert.NotEmpty(SecretMaterialisationScanner.SitesIn(
            "static string Decode(byte[] m) { return Encoding.UTF8.GetString(m); }"));
        Assert.NotEmpty(SecretMaterialisationScanner.SitesIn(
            "public static string AsText(this byte[] m) => Convert.ToBase64String(m);"));
        Assert.NotEmpty(SecretMaterialisationScanner.SitesIn(
            "void B() { var pw = Encoding.UTF8.GetString(this._stash); }"));

        // Routes that are not GetString at all, which the old sink list would have missed entirely.
        Assert.NotEmpty(SecretMaterialisationScanner.SitesIn("var s = Convert.ToHexString(secret);"));
        Assert.NotEmpty(SecretMaterialisationScanner.SitesIn("var s = new string(chars, 0, written);"));

        // The safe direction stays green, or the WinRM script encoder could not be written at all.
        Assert.Empty(SecretMaterialisationScanner.SitesIn("var bytes = Encoding.Unicode.GetBytes(script);"));
        Assert.Empty(SecretMaterialisationScanner.SitesIn("var raw = Convert.FromBase64String(stream.Value);"));

        // A comment describing the forbidden call is not the call — the module documents #7 at length
        // and flagging the explanation only teaches people to delete the explanation.
        Assert.Empty(SecretMaterialisationScanner.SitesIn(
            "// This previously did Encoding.UTF8.GetString(credential.Secret) and called it transient."));
    }

    [Fact]
    public void The_scan_actually_reads_the_module()
    {
        var files = ScannedDirectories.Sum(SourceScanner.FileCount);
        Assert.True(files > 20, $"the secret-material scan found only {files} source files to read");
    }
}
