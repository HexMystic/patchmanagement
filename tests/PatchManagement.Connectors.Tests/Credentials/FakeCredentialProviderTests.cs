using System.Text;
using PatchManagement.Contracts.Credentials;
using PatchManagement.TestSupport.Credentials;

namespace PatchManagement.Connectors.Tests.Credentials;

/// <summary>
/// Tests for the test double. Worth having because the trap it avoids is subtle enough to have
/// wasted an afternoon in any phase that hits it: <see cref="ResolvedCredential"/>'s constructor
/// <em>aliases</em> the array it is handed and <c>Dispose</c> zeroes it in place, so a provider that
/// returns the same array twice hands out zeros the second time — and the failure surfaces as an
/// authentication error, pointing at the connector rather than at the fixture.
/// </summary>
public sealed class FakeCredentialProviderTests
{
    private static readonly CredentialRef Reference = new(Guid.Parse("44444444-4444-4444-4444-444444444444"));

    [Fact]
    public async Task Resolving_after_a_previous_credential_was_disposed_still_returns_usable_material()
    {
        var provider = new FakeCredentialProvider();
        provider.AddSecret(Reference, "the-secret", CredentialKind.SshKey, "labadmin");

        var first = await provider.ResolveAsync(Reference, CancellationToken.None);
        first.Dispose(); // zeroes the array it was handed

        using var second = await provider.ResolveAsync(Reference, CancellationToken.None);

        Assert.Equal("the-secret", Encoding.UTF8.GetString(second.Secret));
    }

    [Fact]
    public async Task Two_live_credentials_from_one_reference_do_not_share_a_buffer()
    {
        var provider = new FakeCredentialProvider();
        provider.AddSecret(Reference, "the-secret", CredentialKind.SshKey);

        using var first = await provider.ResolveAsync(Reference, CancellationToken.None);
        var second = await provider.ResolveAsync(Reference, CancellationToken.None);
        second.Dispose();

        // Disposing one must not blank the other; aliasing here would make a connector that resolves
        // a login key and a sudo password destroy one by releasing the other.
        Assert.Equal("the-secret", Encoding.UTF8.GetString(first.Secret));
    }

    [Fact]
    public async Task An_unregistered_reference_fails_loudly_rather_than_returning_empty_material()
    {
        var provider = new FakeCredentialProvider();

        var ex = await Assert.ThrowsAsync<KeyNotFoundException>(
            () => provider.ResolveAsync(Reference, CancellationToken.None));

        // Empty material would surface as an auth failure and send the reader hunting through the
        // connector for a bug that is really a missing line in the test setup.
        Assert.Contains(Reference.Id.ToString(), ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_sentinel_helper_mints_a_distinct_value_per_call()
    {
        var provider = new FakeCredentialProvider();
        var a = provider.AddSentinel(new CredentialRef(Guid.NewGuid()));
        var b = provider.AddSentinel(new CredentialRef(Guid.NewGuid()));

        // A never-log sweep for a reused sentinel could match a leak from an earlier test and report
        // a failure in the wrong place — or match nothing and pass for the wrong reason.
        Assert.NotEqual(Encoding.UTF8.GetString(a), Encoding.UTF8.GetString(b));
    }

    [Fact]
    public async Task The_recording_decorator_observes_the_consumer_zeroing_the_buffer()
    {
        var provider = new FakeCredentialProvider();
        provider.AddSecret(Reference, "the-secret", CredentialKind.SshKey);
        var recorder = new RecordingCredentialProvider(provider);

        var credential = await recorder.ResolveAsync(Reference, CancellationToken.None);
        Assert.False(recorder.AllHandedOutBuffersAreZeroed, "sanity: a live credential should not read as zeroed");

        credential.Dispose();
        Assert.True(recorder.AllHandedOutBuffersAreZeroed);
    }
}
