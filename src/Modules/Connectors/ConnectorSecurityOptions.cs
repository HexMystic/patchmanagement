namespace PatchManagement.Connectors;

/// <summary>
/// Transport security posture. Bound to configuration section <c>Connectors:Security</c>.
/// </summary>
public sealed class ConnectorSecurityOptions
{
    public const string SectionName = "Connectors:Security";

    /// <summary>
    /// Whether an endpoint with <b>no pinned key yet</b> may be pinned on first sight. <b>False by
    /// default.</b>
    ///
    /// <para><b>Its meaning narrowed when D-301 landed, and the narrowing is the point.</b> With no
    /// key store this was the whole host-key decision — a blanket yes/no in which no fingerprint was
    /// ever read or remembered. Now it answers one question only: <i>may we trust something we have
    /// never seen before?</i> It does <b>not</b> govern an endpoint whose key is already pinned. A
    /// key that CHANGED is refused whatever this is set to, because otherwise the lab's convenience
    /// opt-in — set by every fleet test and fixture — would switch off the only check capable of
    /// detecting an endpoint being impersonated, and the store would be an audit log rather than a
    /// control. See <c>HostKeyGate.Judge</c>.</para>
    ///
    /// <para>The factory previously accepted whatever key the far end presented, unconditionally.
    /// That makes every connection trivially interceptable: anything that can answer on the target's
    /// address is authenticated as the target, and the connector then sends it a private key. For a
    /// product whose entire job is privileged remote execution across an estate, that is the wrong
    /// default no matter how convenient it is in a lab.</para>
    ///
    /// <para>Turning it on is a deliberate, per-environment decision. The dev lab sets it explicitly,
    /// because its containers are rebuilt constantly and generate fresh host keys each time — there
    /// is nothing stable to pin.</para>
    ///
    /// <para><b>What it means with a store registered</b> (<c>IHostKeyStore</c>, D-301, closed
    /// 2026-08-29): true is trust-on-first-use — the first key an endpoint presents is pinned and
    /// every later connection is verified against it. False is stricter still: an endpoint with no
    /// pin is refused, and the key it offered is recorded <c>pending</c> so an operator promotes it
    /// by review rather than by rediscovery. Either way a changed key is refused.</para>
    ///
    /// <para><b>With no store registered</b> the pre-D-301 posture remains: this flag is the entire
    /// decision, and false is what keeps the connector off a real fleet. HARD-PROBLEMS #11 rejects
    /// trust-on-first-use WITHOUT persistence outright — a pin that does not survive a restart is
    /// indistinguishable from trusting everything — so TOFU is only offered where a store exists to
    /// remember it.</para>
    /// </summary>
    public bool AllowUnknownHostKeys { get; set; }
}
