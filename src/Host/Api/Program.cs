using Microsoft.EntityFrameworkCore;
using PatchManagement.Api;
using PatchManagement.Api.Tenancy;
using PatchManagement.Persistence;

var builder = WebApplication.CreateBuilder(args);

// Discover and register all feature modules (Phase 1: Persistence). See CompositionRoot.
builder.Services.AddModules(builder.Configuration);
builder.Services.AddSingleton<ITenantResolver, HeaderTenantResolver>();

var app = builder.Build();

// Tenant context must be established before any tenant-scoped DB access.
app.UseMiddleware<TenantContextMiddleware>();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// Diagnostic endpoint: a real tenant-scoped read that goes through the app role + RLS.
// With no X-Tenant-Id header, RLS denies all rows (returns empty) — fail closed.
app.MapGet("/diag/assets", async (AppDbContext db, CancellationToken ct) =>
{
    var hostnames = await db.Assets
        .OrderBy(a => a.Hostname)
        .Select(a => a.Hostname)
        .ToListAsync(ct);
    return Results.Ok(new { count = hostnames.Count, hostnames });
});

app.Run();

// Exposed so the integration test's WebApplicationFactory<Program> can host the app.
public partial class Program;
