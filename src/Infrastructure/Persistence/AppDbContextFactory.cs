using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace PatchManagement.Persistence;

/// <summary>
/// Design-time factory for <c>dotnet ef</c>. Migrations run as the OWNER/migration role
/// (<c>patchmgmt</c>) — never the restricted app role — so DDL and grants can be applied.
/// Override the connection via <c>PATCHMGMT_MIGRATOR_CONNECTION</c>.
/// </summary>
public sealed class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        var cs = Environment.GetEnvironmentVariable("PATCHMGMT_MIGRATOR_CONNECTION")
                 ?? "Host=localhost;Port=5432;Database=patchmgmt;Username=patchmgmt;Password=patchmgmt";

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(cs)
            .UseSnakeCaseNamingConvention()
            .Options;

        return new AppDbContext(options);
    }
}
