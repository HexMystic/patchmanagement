using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Services;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Enforces the redaction boundaries recorded in ADR 0012, so the two channels the belt does NOT
/// filter cannot silently start carrying secrets. Same shape as the RLS exemption list named in
/// CLAUDE.md §4.1: the accepted limitation is asserted by test, so widening it is a deliberate edit
/// rather than an accident.
/// </summary>
public sealed class VaultLoggingConventionTests
{
    private const string PassThroughFile = "SecretRedactingLoggerProvider.cs";
    private const string PassThroughSignature = "public IDisposable? BeginScope<TState>(TState state)";

    /// <summary>
    /// ADR 0012 decision B: scope state is forwarded unscrubbed, accepted only because nothing
    /// creates a data-carrying scope. This is the guard — and it matters more than usual, because
    /// the capturing logger behind NeverLogTests discards scope state, so that suite would stay
    /// green while a scoped secret leaked to real sinks.
    /// </summary>
    [Fact]
    public void Vault_module_creates_no_logging_scopes()
    {
        var root = RepoRoot();
        var vaultSrc = Path.Combine(root.FullName, "src", "Modules", "Vault");
        Assert.True(Directory.Exists(vaultSrc), $"Expected vault sources at '{vaultSrc}'.");

        var offenders = new List<string>();

        foreach (var file in Directory.EnumerateFiles(vaultSrc, "*.cs", SearchOption.AllDirectories))
        {
            if (IsBuildOutput(file)) continue;

            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                if (!lines[i].Contains("BeginScope", StringComparison.Ordinal)) continue;
                if (IsKnownPassThrough(file, lines[i])) continue;

                offenders.Add($"  {Path.GetRelativePath(root.FullName, file)}:{i + 1}: {lines[i].Trim()}");
            }
        }

        Assert.True(offenders.Count == 0,
            "Logging scopes are not scrubbed by SecretRedactingLoggerProvider (ADR 0012 decision B), and "
            + "NeverLogTests cannot see scope state. Either scrub the state or amend the ADR:\n"
            + string.Join("\n", offenders));
    }

    /// <summary>
    /// ADR 0012 decision C: a type carrying secret material must not render it. Behavioural — the
    /// secret is a sentinel and the rendered form is swept in the same four encodings NeverLogTests
    /// uses, so a change of field type or a lost override fails here immediately.
    /// </summary>
    [Fact]
    public void Secret_bearing_types_do_not_expose_the_secret_via_ToString()
    {
        var secret = Encoding.UTF8.GetBytes("CONVENTION-SENTINEL-" + Guid.NewGuid().ToString("N"));

        // A record: safe only because Secret is byte[], which the generated ToString() renders as
        // "System.Byte[]". As a string it would print verbatim.
        var request = new StoreCredentialRequest("cred", CredentialKind.WindowsPassword, secret, "domain-admin");
        AssertRendersNoSecret(request.ToString(), secret, nameof(StoreCredentialRequest));

        // A class with a hand-written redacted ToString(). Copy the bytes: Dispose zeroes the array.
        using var resolved = new ResolvedCredential(CredentialKind.WindowsPassword, secret.ToArray(), "domain-admin");
        AssertRendersNoSecret(resolved.ToString(), secret, nameof(ResolvedCredential));
    }

    /// <summary>
    /// Keeps the test above honest as the code grows: any NEW record carrying a secret-looking
    /// member must be added to the covered list (and to the behavioural test), or it fails here.
    /// Records are the risk because their compiler-generated ToString() prints every property.
    /// </summary>
    [Fact]
    public void No_secret_bearing_record_escapes_the_ToString_check()
    {
        // Deliberately narrow. "key"/"token" would match KeyId, KekKeyset, and similar non-plaintext
        // members and drown the signal in false positives. An enforcement aid, not a completeness proof.
        string[] vocabulary = ["secret", "password", "passphrase", "plaintext", "credential"];

        Type[] covered = [typeof(StoreCredentialRequest)];

        Assembly[] assemblies =
        [
            typeof(StoreCredentialRequest).Assembly,   // PatchManagement.Vault
            typeof(ResolvedCredential).Assembly,       // PatchManagement.Contracts
        ];

        var uncovered = assemblies
            .SelectMany(a => a.GetTypes())
            .Where(IsRecord)
            .Where(t => SecretishMembers(t, vocabulary).Any())
            .Distinct()
            .Except(covered)
            .Select(t => $"  {t.FullName} ({string.Join(", ", SecretishMembers(t, vocabulary).Select(m => m.Name))})")
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToArray();

        Assert.True(uncovered.Length == 0,
            "These records carry secret-looking members and would print them from the compiler-generated "
            + "ToString() (ADR 0012 decision C). Give them a redacted ToString() or cover them in "
            + $"{nameof(Secret_bearing_types_do_not_expose_the_secret_via_ToString)}:\n"
            + string.Join("\n", uncovered));
    }

    private static void AssertRendersNoSecret(string rendered, byte[] secret, string what)
    {
        Assert.False(rendered.Contains(Encoding.UTF8.GetString(secret), StringComparison.Ordinal),
            $"{what}.ToString() rendered the secret as UTF-8 text: {rendered}");
        Assert.False(rendered.Contains(Convert.ToBase64String(secret), StringComparison.Ordinal),
            $"{what}.ToString() rendered the secret as base64: {rendered}");
        Assert.False(rendered.Contains(Convert.ToHexString(secret), StringComparison.OrdinalIgnoreCase),
            $"{what}.ToString() rendered the secret as hex: {rendered}");
    }

    private static bool IsRecord(Type type) =>
        type.GetMethod("<Clone>$", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic) is not null;

    private static IEnumerable<MemberInfo> SecretishMembers(Type type, string[] vocabulary) =>
        type.GetMembers(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(m => m is PropertyInfo or FieldInfo)
            .Where(m => !m.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false))
            .Where(m => vocabulary.Any(v => m.Name.Contains(v, StringComparison.OrdinalIgnoreCase)))
            .Where(m => MemberType(m) == typeof(byte[]) || MemberType(m) == typeof(string));

    private static Type MemberType(MemberInfo member) =>
        member is PropertyInfo property ? property.PropertyType : ((FieldInfo)member).FieldType;

    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

    private static bool IsKnownPassThrough(string file, string line) =>
        Path.GetFileName(file) == PassThroughFile
        && line.Contains(PassThroughSignature, StringComparison.Ordinal);

    /// <summary>Anchors the source scan on the checkout, not the working directory.</summary>
    private static DirectoryInfo RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "PatchManagement.sln")))
            dir = dir.Parent;

        return dir ?? throw new InvalidOperationException(
            $"Could not locate PatchManagement.sln walking up from '{AppContext.BaseDirectory}'. "
            + "This convention test scans source files and needs the repo checkout present.");
    }
}
