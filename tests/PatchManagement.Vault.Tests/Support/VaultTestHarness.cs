using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PatchManagement.Contracts.Auditing;
using PatchManagement.Persistence;
using PatchManagement.Persistence.Auditing;
using PatchManagement.Persistence.Entities;
using PatchManagement.Persistence.Rls;
using PatchManagement.Vault.KeyProviders;
using PatchManagement.Vault.Services;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// Wires the vault against the ephemeral database exactly as production would: a per-tenant,
/// RLS-scoped <see cref="AppDbContext"/> on the restricted app role for store/resolve, and an
/// owner-scoped context for the cross-tenant KEK rotation. A SINGLE <see cref="IKeyProvider"/>
/// instance is shared so KEK versions stay consistent across store and rotate.
/// </summary>
public sealed class VaultTestHarness
{
    private readonly PostgresFixture _fx;

    public VaultTestHarness(PostgresFixture fx, IKeyProvider? keyProvider = null)
    {
        _fx = fx;
        // Defaults to the fixture's collection-wide keyset, not a fresh one: cross-tenant KEK
        // rotation re-wraps every DEK in the shared database, so a per-harness keyset would leave
        // rotation unable to unwrap DEKs another test class created. See PostgresFixture.
        KeyProvider = keyProvider ?? fx.SharedKeyProvider;
    }

    public IKeyProvider KeyProvider { get; }

    /// <summary>Seed a tenant (as owner, bypassing RLS) so tenant-scoped FKs/RLS accept its rows.</summary>
    public async Task SeedTenantAsync(Guid tenantId, string name)
    {
        await using var db = OwnerContext();
        if (await db.Tenants.AnyAsync(t => t.Id == tenantId)) return;
        var now = DateTimeOffset.UtcNow;
        db.Tenants.Add(new Tenant { Id = tenantId, Name = name, Status = "active", CreatedAt = now, UpdatedAt = now });
        await db.SaveChangesAsync();
    }

    /// <summary>An RLS-scoped context on the restricted app role, pinned to <paramref name="tenantId"/>.</summary>
    public AppDbContext AppContext(Guid tenantId)
    {
        var tenant = new TenantContextAccessor { TenantId = tenantId };
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(_fx.AppConnectionString)
            .AddInterceptors(new RlsConnectionInterceptor(tenant))
            .UseSnakeCaseNamingConvention()
            .Options;
        return new AppDbContext(options);
    }

    /// <summary>An owner context that bypasses RLS — for seeding and cross-tenant rotation.</summary>
    public AppDbContext OwnerContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(_fx.OwnerConnectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        return new AppDbContext(options);
    }

    /// <summary>Build a vault provider bound to <paramref name="db"/> for the given tenant.</summary>
    public VaultCredentialProvider Provider(
        AppDbContext db, Guid tenantId, ILogger<VaultCredentialProvider>? logger = null, IAuditLog? audit = null)
    {
        var tenant = new TenantContextAccessor { TenantId = tenantId };
        var dataKeys = new DataKeyService(db, KeyProvider, tenant);
        return new VaultCredentialProvider(
            db, dataKeys, audit ?? new EfAuditLog(db), new SystemVaultActor(), tenant,
            logger ?? NullLogger<VaultCredentialProvider>.Instance);
    }

    /// <summary>Build the cross-tenant rotation service over an owner context.</summary>
    public KekRotationService Rotation(AppDbContext ownerDb, IAuditLog? audit = null) =>
        new(ownerDb, KeyProvider, audit ?? new EfAuditLog(ownerDb), new SystemVaultActor(),
            NullLogger<KekRotationService>.Instance);
}
