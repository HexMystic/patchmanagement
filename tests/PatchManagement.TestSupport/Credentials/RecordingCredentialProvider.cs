using System.Collections.Concurrent;
using PatchManagement.Contracts.Credentials;

namespace PatchManagement.TestSupport.Credentials;

/// <summary>
/// Decorator that records what was resolved and — the useful part — keeps a reference to each array
/// handed out, so a test can assert the consumer actually zeroed it.
///
/// <para>This is how "the connector disposes every credential it resolves" becomes checkable rather
/// than asserted by inspection. <see cref="ResolvedCredential.Dispose"/> zeroes in place, so a
/// buffer that is still non-zero after the operation returned proves the consumer leaked it —
/// including on the paths that are easy to get wrong: auth failure, timeout and cancellation.</para>
/// </summary>
public sealed class RecordingCredentialProvider(ICredentialProvider inner) : ICredentialProvider
{
    private readonly ConcurrentQueue<byte[]> _handedOut = new();
    private readonly ConcurrentQueue<CredentialRef> _resolved = new();

    /// <summary>Every reference resolved, in order, including repeats.</summary>
    public IReadOnlyCollection<CredentialRef> Resolved => _resolved;

    public int ResolveCount => _resolved.Count;

    /// <summary>How many times a specific reference was resolved.</summary>
    public int CountFor(CredentialRef reference) => _resolved.Count(r => r.Id == reference.Id);

    /// <summary>True when every array handed out has been zeroed by its consumer.</summary>
    public bool AllHandedOutBuffersAreZeroed => _handedOut.All(b => b.All(x => x == 0));

    /// <summary>
    /// Buffers still holding non-zero bytes. Non-empty means a consumer failed to dispose;
    /// exposed as a count rather than content so a failure message can never print key material.
    /// </summary>
    public int UnzeroedBufferCount => _handedOut.Count(b => b.Any(x => x != 0));

    public async Task<ResolvedCredential> ResolveAsync(CredentialRef reference, CancellationToken ct)
    {
        var credential = await inner.ResolveAsync(reference, ct).ConfigureAwait(false);
        _resolved.Enqueue(reference);

        // Capture the backing array itself, not a copy: the point is to observe the consumer
        // zeroing this exact buffer. Secret is a ReadOnlySpan<byte>, so reach it while it is alive.
        if (!credential.Secret.IsEmpty)
        {
            var backing = GetBackingArray(credential);
            if (backing is not null) _handedOut.Enqueue(backing);
        }

        return credential;
    }

    // ResolvedCredential exposes its secret only as a ReadOnlySpan<byte>, which cannot be stored.
    // The private field is the only way to hold the same array the consumer will zero; a copy would
    // stay non-zero forever and make every assertion fail. Reflection is confined to this one place.
    private static byte[]? GetBackingArray(ResolvedCredential credential) =>
        typeof(ResolvedCredential)
            .GetField("_secret", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.GetValue(credential) as byte[];
}
