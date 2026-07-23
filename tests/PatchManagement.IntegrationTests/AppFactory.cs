using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace PatchManagement.IntegrationTests;

/// <summary>
/// Hosts the real API (Program) but points its restricted "App" connection string at the
/// throwaway Testcontainers database. Requests therefore go through the genuine pipeline:
/// tenant middleware -> app role -> RLS.
/// </summary>
public sealed class AppFactory(string appConnectionString) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:App", appConnectionString);
    }
}
