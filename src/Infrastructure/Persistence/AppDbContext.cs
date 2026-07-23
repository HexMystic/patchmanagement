using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using PatchManagement.Contracts.States;
using PatchManagement.Persistence.Entities;

namespace PatchManagement.Persistence;

/// <summary>
/// The application DbContext. Every entity except <see cref="Tenant"/> carries <c>tenant_id</c>
/// and is protected by RLS (policies + FORCE are applied in the migration SQL). Column names are
/// snake_cased by convention (configured in <c>AddPersistence</c> and the design-time factory).
/// </summary>
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<Operator> Operators => Set<Operator>();
    public DbSet<Credential> Credentials => Set<Credential>();
    public DbSet<DataKey> DataKeys => Set<DataKey>();
    public DbSet<AuditLogEntry> AuditLog => Set<AuditLogEntry>();
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<AssetPackage> AssetPackages => Set<AssetPackage>();
    public DbSet<Finding> Findings => Set<Finding>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        var stateConverter = new ValueConverter<EndpointState, string>(
            v => v.ToDbValue(),
            v => EndpointStateNames.FromDbValue(v));

        b.Entity<Tenant>(e =>
        {
            e.ToTable("tenants");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).IsRequired();
            e.Property(x => x.Status).IsRequired();
        });

        b.Entity<Operator>(e =>
        {
            e.ToTable("operators");
            e.HasKey(x => x.Id);
            e.Property(x => x.Email).IsRequired();
            e.HasIndex(x => new { x.TenantId, x.Email }).IsUnique();
        });

        b.Entity<Credential>(e =>
        {
            e.ToTable("credentials");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).IsRequired();
            e.Property(x => x.Kind).HasConversion<string>();
        });

        b.Entity<DataKey>(e =>
        {
            e.ToTable("data_keys");
            e.HasKey(x => x.Id);
        });

        b.Entity<AuditLogEntry>(e =>
        {
            e.ToTable("audit_log");
            e.HasKey(x => x.Id);
            e.Property(x => x.Actor).IsRequired();
            e.Property(x => x.Action).IsRequired();
            e.Property(x => x.Target).IsRequired();
            e.Property(x => x.Detail).HasColumnType("jsonb");
            e.HasIndex(x => new { x.TenantId, x.At });
        });

        b.Entity<Asset>(e =>
        {
            e.ToTable("assets");
            e.HasKey(x => x.Id);
            e.Property(x => x.Hostname).IsRequired();
            e.Property(x => x.Source).IsRequired();
            e.Property(x => x.State).HasConversion(stateConverter).IsRequired();
            e.HasIndex(x => new { x.TenantId, x.Hostname });
        });

        b.Entity<AssetPackage>(e =>
        {
            e.ToTable("asset_packages");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).IsRequired();
            e.Property(x => x.Version).IsRequired();
            e.HasIndex(x => new { x.TenantId, x.AssetId });
        });

        b.Entity<Finding>(e =>
        {
            e.ToTable("findings");
            e.HasKey(x => x.Id);
            e.Property(x => x.State).HasConversion(stateConverter).IsRequired();
            e.Property(x => x.RiskExplanation).HasColumnType("jsonb");
            e.HasIndex(x => new { x.TenantId, x.AssetId });
            e.HasIndex(x => new { x.TenantId, x.State });
        });
    }
}
