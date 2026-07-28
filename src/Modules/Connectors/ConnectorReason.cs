namespace PatchManagement.Connectors;

/// <summary>
/// Bounded reason codes for connector diagnostics.
///
/// <para><b>Why these exist.</b> A failure message set by the connector flows into
/// <c>FileResult.Detail</c> / <c>CommandResult.Detail</c>, and a caller will log that. Building such
/// a message from remote output — stderr, a tool's error text, the command line — forwards content
/// the connector does not control and cannot inspect into a channel it does not own. Remote stderr
/// routinely quotes back the command that failed, and a command line is the likeliest place for a
/// caller-embedded secret (ADR 0012 decision C is the same argument applied to
/// <c>ToString()</c>).</para>
///
/// <para>These codes are compile-time constants, so a diagnostic can never carry anything the
/// endpoint chose. The remote output is not discarded — it stays on <c>CommandResult.StandardError</c>
/// and <c>StandardOutput</c>, where it is the caller's payload rather than the module's diagnostic.
/// That distinction is the whole point: <b>returning</b> remote output is fine, <b>describing a
/// failure with it</b> is not.</para>
///
/// <para>They are stable identifiers, not prose: an operator greps for them and a UI maps them to a
/// localised string.</para>
/// </summary>
public static class ConnectorReason
{
    /// <summary>
    /// An unexpected transport-layer exception — one the connector does not model — was contained at
    /// the connector boundary and turned into a typed result.
    ///
    /// <para>It exists because "the transport only throws what we translate" is an assumption, and it
    /// was wrong: SSH.NET threw <c>InvalidOperationException</c> from the stdin path and it escaped
    /// <c>RunAsync</c> raw, past a contract that promises typed results (CLAUDE.md §5) and into
    /// ASP.NET's logger outside any redaction scope (ADR 0012's residual for this phase). The code is
    /// deliberately bounded and carries none of the exception's text, for the same reason every other
    /// code here does.</para>
    /// </summary>
    public const string TransportFault = "transport-fault";

    public const string WinRmUploadFailed = "winrm-upload-failed";
    public const string WinRmDownloadFailed = "winrm-download-failed";
    public const string FactsCommandFailed = "facts-command-failed";
    public const string FactsCommandNonZeroExit = "facts-command-nonzero-exit";
    public const string FactsUnsupportedProtocol = "facts-unsupported-protocol";
}
