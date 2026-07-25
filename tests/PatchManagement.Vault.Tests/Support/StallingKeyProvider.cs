using PatchManagement.Vault.KeyProviders;

namespace PatchManagement.Vault.Tests.Support;

/// <summary>
/// Forces one specific interleave of two concurrent rotations, so the cold-review H2 defect is
/// demonstrated deterministically rather than raced for.
///
/// <para>It delegates everything to the real provider, except that the <b>first</b>
/// <see cref="WrapAsync"/> call parks until the test releases it. That call happens inside the first
/// rotation's convergence sweep, immediately after that rotation has already minted its key — which
/// is precisely the window in which a second rotation can mint again and move the current version
/// out from under the first.</para>
///
/// <para><see cref="Released"/> is awaited with a timeout on purpose. Once the sweep guard exists
/// the second rotation cannot proceed at all, so the signal the test would otherwise wait for never
/// arrives; without the timeout the fixed code would deadlock instead of passing.</para>
/// </summary>
public sealed class StallingKeyProvider(IKeyProvider inner) : IKeyProvider
{
    private readonly TaskCompletionSource _stalled = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _wrapCalls;

    /// <summary>Completes once a rotation has parked inside its sweep.</summary>
    public Task Stalled => _stalled.Task;

    /// <summary>How long a parked rotation waits before giving up and continuing.</summary>
    public TimeSpan StallTimeout { get; init; } = TimeSpan.FromSeconds(5);

    public void Release() => _release.TrySetResult();

    public Task<string> GetCurrentKeyIdAsync(CancellationToken ct) => inner.GetCurrentKeyIdAsync(ct);

    public Task<string> RefreshCurrentKeyIdAsync(CancellationToken ct) => inner.RefreshCurrentKeyIdAsync(ct);

    public Task<string> RotateMasterKeyAsync(CancellationToken ct) => inner.RotateMasterKeyAsync(ct);

    public Task<byte[]> UnwrapAsync(byte[] wrappedDek, string keyId, KeyBinding binding, CancellationToken ct) =>
        inner.UnwrapAsync(wrappedDek, keyId, binding, ct);

    public async Task<byte[]> WrapAsync(byte[] dek, string keyId, KeyBinding binding, CancellationToken ct)
    {
        if (Interlocked.Increment(ref _wrapCalls) == 1)
        {
            _stalled.TrySetResult();
            await Task.WhenAny(_release.Task, Task.Delay(StallTimeout, ct));
        }

        return await inner.WrapAsync(dek, keyId, binding, ct);
    }
}
