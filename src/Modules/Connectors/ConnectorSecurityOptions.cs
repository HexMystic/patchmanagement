namespace PatchManagement.Connectors;

/// <summary>
/// Transport security posture. Bound to configuration section <c>Connectors:Security</c>.
/// </summary>
public sealed class ConnectorSecurityOptions
{
    public const string SectionName = "Connectors:Security";

    /// <summary>
    /// Whether to connect to a host whose key is not verified. <b>False by default.</b>
    ///
    /// <para>The factory previously accepted whatever key the far end presented, unconditionally.
    /// That makes every connection trivially interceptable: anything that can answer on the target's
    /// address is authenticated as the target, and the connector then sends it a private key. For a
    /// product whose entire job is privileged remote execution across an estate, that is the wrong
    /// default no matter how convenient it is in a lab.</para>
    ///
    /// <para>Turning it on is a deliberate, per-environment decision. The dev lab sets it explicitly,
    /// because its containers are rebuilt constantly and generate fresh host keys each time — there
    /// is nothing stable to pin. A real fleet must NOT enable it; it needs a verified-key store,
    /// which is deferred with a named owner (D-301, Phase 4, where asset persistence lives). Until
    /// that lands this flag is the gate that stops the connector being pointed at production, and
    /// that gating is the point rather than a side effect.</para>
    /// </summary>
    public bool AllowUnknownHostKeys { get; set; }
}
