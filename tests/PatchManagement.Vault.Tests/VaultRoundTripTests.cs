using System.Text;
using Microsoft.EntityFrameworkCore;
using PatchManagement.Contracts.Credentials;
using PatchManagement.Vault.Services;
using PatchManagement.Vault.Tests.Support;
using Xunit;

namespace PatchManagement.Vault.Tests;

/// <summary>
/// End-to-end vault behaviour against the ephemeral database, through the restricted app role with
/// RLS enforced — the production path. Covers the phase-2 exit criteria: round-trip, per-tenant DEK
/// isolation, and metadata-only audit of every access.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class VaultRoundTripTests(PostgresFixture fx)
{
    private static readonly Guid TenantA = Guid.NewGuid();
    private static readonly Guid TenantB = Guid.NewGuid();

    [Fact]
    public async Task Software_provider_round_trips_a_credential()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        var secret = Encoding.UTF8.GetBytes("s3cr3t-" + Guid.NewGuid());

        CredentialRef reference;
        await using (var db = harness.AppContext(TenantA))
        {
            var vault = harness.Provider(db, TenantA);
            reference = await vault.StoreAsync(
                new StoreCredentialRequest("web-admin", CredentialKind.WindowsPassword, secret, "administrator"),
                CancellationToken.None);
        }

        await using (var db = harness.AppContext(TenantA))
        {
            var vault = harness.Provider(db, TenantA);
            using var resolved = await vault.ResolveAsync(reference, CancellationToken.None);

            Assert.Equal(CredentialKind.WindowsPassword, resolved.Kind);
            Assert.Equal("administrator", resolved.Username);
            Assert.Equal(secret, resolved.Secret.ToArray());
        }
    }

    [Fact]
    public async Task Plaintext_is_never_written_to_the_credentials_row()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        var secret = Encoding.UTF8.GetBytes("plaintext-marker-" + Guid.NewGuid());

        CredentialRef reference;
        await using (var db = harness.AppContext(TenantA))
        {
            var vault = harness.Provider(db, TenantA);
            reference = await vault.StoreAsync(
                new StoreCredentialRequest("k", CredentialKind.SshKey, secret), CancellationToken.None);
        }

        await using var owner = harness.OwnerContext();
        var row = await owner.Credentials.SingleAsync(c => c.Id == reference.Id);
        Assert.NotNull(row.Envelope);
        // The envelope must NOT contain the plaintext bytes anywhere.
        Assert.False(Contains(row.Envelope!, secret), "envelope must not contain the plaintext secret");
    }

    [Fact]
    public async Task Each_tenant_gets_its_own_dek_and_cannot_resolve_the_other()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        await harness.SeedTenantAsync(TenantB, "B");

        CredentialRef refA;
        await using (var db = harness.AppContext(TenantA))
        {
            refA = await harness.Provider(db, TenantA).StoreAsync(
                new StoreCredentialRequest("a", CredentialKind.SshKey, Encoding.UTF8.GetBytes("aaa")),
                CancellationToken.None);
        }
        await using (var db = harness.AppContext(TenantB))
        {
            await harness.Provider(db, TenantB).StoreAsync(
                new StoreCredentialRequest("b", CredentialKind.SshKey, Encoding.UTF8.GetBytes("bbb")),
                CancellationToken.None);
        }

        // Tenant B resolving Tenant A's ref sees nothing — RLS hides the row (blast-radius containment).
        await using (var db = harness.AppContext(TenantB))
        {
            var vault = harness.Provider(db, TenantB);
            await Assert.ThrowsAsync<KeyNotFoundException>(() => vault.ResolveAsync(refA, CancellationToken.None));
        }

        // Distinct DEK rows exist per tenant.
        await using var owner = harness.OwnerContext();
        var dekTenants = await owner.DataKeys.Select(k => k.TenantId).Distinct().ToListAsync();
        Assert.Contains(TenantA, dekTenants);
        Assert.Contains(TenantB, dekTenants);
    }

    [Fact]
    public async Task Every_credential_access_is_audited_with_metadata_only()
    {
        var harness = new VaultTestHarness(fx);
        await harness.SeedTenantAsync(TenantA, "A");
        var secret = Encoding.UTF8.GetBytes("audit-secret-" + Guid.NewGuid());

        CredentialRef reference;
        await using (var db = harness.AppContext(TenantA))
        {
            var vault = harness.Provider(db, TenantA);
            reference = await vault.StoreAsync(
                new StoreCredentialRequest("audited", CredentialKind.WindowsPassword, secret, "admin"),
                CancellationToken.None);
            using var _ = await vault.ResolveAsync(reference, CancellationToken.None);
        }

        await using var owner = harness.OwnerContext();
        var entries = await owner.AuditLog
            .Where(a => a.TenantId == TenantA && a.Target == $"cred:{reference.Id}")
            .ToListAsync();

        Assert.Contains(entries, e => e.Action == "credential.store");
        Assert.Contains(entries, e => e.Action == "credential.resolve");
        // Metadata only — no secret material, plaintext or base64, in any audit field.
        foreach (var e in entries)
        {
            var blob = $"{e.Actor}|{e.Action}|{e.Target}|{e.Detail}";
            Assert.DoesNotContain(Encoding.UTF8.GetString(secret), blob);
            Assert.DoesNotContain(Convert.ToBase64String(secret), blob);
        }
    }

    private static bool Contains(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return false;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
