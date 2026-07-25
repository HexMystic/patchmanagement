using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// Fences the cross-tenant seam ADR 0014 introduced (re-review H-D).
///
/// <para>ADR 0014's "no elevation is involved" is true at the DATABASE layer — no new role, no
/// <c>BYPASSRLS</c>, no connection string, and every scope is a concrete tenant under
/// <c>FORCE ROW LEVEL SECURITY</c>. It was overstated at the APPLICATION layer:
/// <c>ListTenantsAsync</c> hands a caller the entire tenant registry, which no ordinary
/// tenant-scoped request can obtain, and <c>Create(tenantId)</c> opens a scope for any tenant while
/// writing no audit row — so the ADR's "misuse is attributable" rests on callers voluntarily
/// auditing inside a sweep.</para>
///
/// <para>The ADR recorded that residual risk as unenforceable in DI, which is true — and left it
/// there. This makes it enforceable the same way ADR 0012 decision B made the unscrubbed scope
/// channel enforceable: a source scan with an explicit allowlist, so widening the blast radius is a
/// deliberate edit someone has to defend rather than an accident. It is not authorization; Phase 14
/// supplies that and should gate the trigger.</para>
///
/// <para>The convention is repo-wide even though the test lives in the vault project: this is where
/// the source-scanning idiom already lives, and Phase 2 owns the finding. It needs no database.</para>
/// </summary>
public sealed class TenantScopeConventionTests
{
    /// <summary>
    /// Files permitted to name the seam: its declaration, its one implementation, the DI
    /// registration, and the single legitimate consumer — KEK rotation, which is background work by
    /// construction and audits every tenant it touches.
    ///
    /// <para>Adding to this list means adding a cross-tenant capability. Phases 8 (wave execution)
    /// and 11 (schedules) are expected to appear here eventually, per ADR 0014 — and each should
    /// audit per tenant, as rotation does. Anything reachable from an HTTP request must not.</para>
    /// </summary>
    private static readonly string[] Allowed =
    [
        Path.Combine("src", "Shared", "Contracts", "Tenancy", "ITenantScopeFactory.cs"),
        Path.Combine("src", "Infrastructure", "Persistence", "Rls", "TenantScopeFactory.cs"),
        Path.Combine("src", "Infrastructure", "Persistence", "PersistenceModule.cs"),
        Path.Combine("src", "Modules", "Vault", "Vault", "KekRotationService.cs"),
        // Doc comments only — these name the seam to explain why they do not use it.
        Path.Combine("src", "Modules", "Vault", "Vault", "IKekRotationService.cs"),
        Path.Combine("src", "Modules", "Vault", "VaultModule.cs"),
    ];

    private static readonly string[] Seam = ["ITenantScopeFactory", "ListTenantsAsync", "SweepAsync"];

    [Fact]
    public void The_cross_tenant_seam_is_used_only_where_it_is_sanctioned()
    {
        var root = RepoRoot();
        var src = Path.Combine(root.FullName, "src");
        Assert.True(Directory.Exists(src), $"Expected sources at '{src}'.");

        var offenders = new List<string>();

        foreach (var file in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories))
        {
            if (IsBuildOutput(file)) continue;

            var relative = Path.GetRelativePath(root.FullName, file);
            if (Allowed.Contains(relative, StringComparer.OrdinalIgnoreCase)) continue;

            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                if (!Seam.Any(s => lines[i].Contains(s, StringComparison.Ordinal))) continue;
                offenders.Add($"  {relative}:{i + 1}: {lines[i].Trim()}");
            }
        }

        Assert.True(offenders.Count == 0,
            "ITenantScopeFactory grants cross-tenant reach that no ordinary request has: it enumerates "
            + "the whole tenant registry and opens a scope for any tenant, and Create() writes no audit "
            + "row (ADR 0014, re-review H-D). Background work only. If this is legitimate, add the file "
            + "to the allowlist here and make it audit per tenant the way KekRotationService does:\n"
            + string.Join("\n", offenders));
    }

    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

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
