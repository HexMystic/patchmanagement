using PatchManagement.Connectors.Ssh;

namespace PatchManagement.Connectors.Tests;

/// <summary>
/// D-301. The trust decision itself, as a pure function — the half that decides whether a private
/// key is about to be sent to whatever answered on the target's address.
///
/// <para>Before the store existed, this decision was the single expression
/// <c>e.CanTrust = _security.AllowUnknownHostKeys</c>: a blanket yes/no in which no fingerprint was
/// ever read, compared or remembered. So the property that actually authenticates an endpoint — that
/// the key it presents today is the key it presented before — had nothing to fail against.</para>
/// </summary>
public sealed class HostKeyGateTests
{
    private static readonly PinnedHostKey Pinned =
        new("ssh-ed25519", "AAAApinnedFINGERPRINTvalue0000000000000000000");

    private const string ADifferentKey = "ZZZZdifferentFINGERPRINTvalue00000000000000000";

    [Fact]
    public void A_key_matching_the_pin_verifies()
    {
        Assert.Equal(
            HostKeyVerdict.Verified,
            HostKeyGate.Judge(Pinned, Pinned.FingerprintSha256, pinsOnFirstSight: false));
    }

    [Fact]
    public void A_first_sighting_is_pinned_when_the_deployment_pins_on_first_sight()
    {
        Assert.Equal(
            HostKeyVerdict.PinnedOnFirstSight,
            HostKeyGate.Judge(pin: null, ADifferentKey, pinsOnFirstSight: true));
    }

    [Fact]
    public void A_first_sighting_is_refused_when_the_deployment_does_not()
    {
        Assert.Equal(
            HostKeyVerdict.Unknown,
            HostKeyGate.Judge(pin: null, ADifferentKey, pinsOnFirstSight: false));
    }

    /// <summary>
    /// <b>The load-bearing case, and the one D-301 exists for.</b> A pinned endpoint presenting a
    /// different key is refused <em>whatever the policy flag says</em>.
    ///
    /// <para><c>AllowUnknownHostKeys</c> answers "may we pin something never seen before". If it also
    /// covered this, the lab's convenience opt-in — which every fleet test and fixture sets — would
    /// switch off the only check that can detect an endpoint being impersonated, and the store would
    /// be an audit log rather than a control.</para>
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_changed_key_is_refused_regardless_of_whether_unknown_keys_are_allowed(bool pinsOnFirstSight)
    {
        Assert.Equal(
            HostKeyVerdict.Changed,
            HostKeyGate.Judge(Pinned, ADifferentKey, pinsOnFirstSight));
    }

    /// <summary>
    /// Fingerprints are compared byte-for-byte. A comparison that ignored case would accept a
    /// different key: base64 is case-significant, so <c>aB</c> and <c>Ab</c> are different digests.
    /// </summary>
    [Fact]
    public void Fingerprint_comparison_is_case_sensitive()
    {
        Assert.Equal(
            HostKeyVerdict.Changed,
            HostKeyGate.Judge(Pinned, Pinned.FingerprintSha256.ToUpperInvariant(), pinsOnFirstSight: true));
    }

    [Fact]
    public async Task An_endpoint_with_no_store_keeps_the_pre_store_posture()
    {
        // Nothing registered a store: the flag is the whole decision, exactly as before D-301. This
        // is the shape the unit suite and the lab fixture still run in, so it must not change.
        var gate = await HostKeyGate.OpenAsync(
            store: null, Guid.NewGuid(), "10.0.0.5", 22, pinsOnFirstSight: true, CancellationToken.None);

        Assert.True(gate.Observe("ssh-ed25519", ADifferentKey, [1, 2, 3]));
        Assert.False(gate.Refused);

        // And recording is a no-op rather than a null dereference.
        await gate.RecordAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_refused_key_is_recorded_as_what_was_presented_rather_than_dropped()
    {
        var store = new FakeHostKeyStore { Trusted = Pinned };
        var tenant = Guid.NewGuid();

        var gate = await HostKeyGate.OpenAsync(
            store, tenant, "10.0.0.5", 22, pinsOnFirstSight: true, CancellationToken.None);

        Assert.False(gate.Observe("ssh-ed25519", ADifferentKey, [9, 9, 9]));
        Assert.True(gate.Refused);

        await gate.RecordAsync(CancellationToken.None);

        // "The key at this endpoint changed" is the security-relevant event. A refusal that wrote
        // nothing would leave the estate unable to tell a rebuilt host from an interception later.
        var recorded = Assert.Single(store.Recorded);
        Assert.Equal(HostKeyVerdict.Changed, recorded.Verdict);
        Assert.Equal(ADifferentKey, recorded.FingerprintSha256);
        Assert.Equal(tenant, recorded.TenantId);
        Assert.Equal("10.0.0.5", recorded.Host);
        Assert.Equal(22, recorded.Port);
    }

    /// <summary>
    /// The refusal has to name both fingerprints. An operator seeing it has exactly one decision to
    /// make — rebuilt host, or interception — and the two keys are the evidence that decision rests
    /// on. Host keys are public material, so printing them engages neither NEVER #1 nor #2.
    /// </summary>
    [Fact]
    public async Task The_refusal_names_the_pinned_and_the_presented_key()
    {
        var gate = await HostKeyGate.OpenAsync(
            new FakeHostKeyStore { Trusted = Pinned },
            Guid.NewGuid(), "10.0.0.5", 22, pinsOnFirstSight: true, CancellationToken.None);

        gate.Observe("ssh-ed25519", ADifferentKey, [9]);
        var refusal = gate.Refusal();

        Assert.Contains(Pinned.FingerprintSha256, refusal.Message, StringComparison.Ordinal);
        Assert.Contains(ADifferentKey, refusal.Message, StringComparison.Ordinal);
        Assert.Contains("10.0.0.5:22", refusal.Message, StringComparison.Ordinal);
    }

    private sealed class FakeHostKeyStore : IHostKeyStore
    {
        public PinnedHostKey? Trusted { get; init; }
        public List<HostKeyObservation> Recorded { get; } = [];

        public Task<PinnedHostKey?> FindTrustedAsync(Guid tenantId, string host, int port, CancellationToken ct) =>
            Task.FromResult(Trusted);

        public Task RecordAsync(HostKeyObservation observation, CancellationToken ct)
        {
            Recorded.Add(observation);
            return Task.CompletedTask;
        }
    }
}
