using System.Text.RegularExpressions;
using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.DoubleHop;

/// <summary>The verdict of inspecting a command for an onward-authentication (double-hop) need.</summary>
public sealed record DoubleHopAssessment(bool RequiresOnwardAuth, string? Reason)
{
    public static readonly DoubleHopAssessment None = new(false, null);
}

/// <summary>
/// Detects the classic WinRM/PS-Remoting "double-hop": a remote session that must authenticate
/// <i>onward</i> to a second host (an SMB/UNC share, another PSSession) cannot do so without
/// credential delegation, and naive designs hang or fail opaquely (HARD-PROBLEMS #9).
///
/// This is static inspection only — it never executes anything. The connector uses the verdict to
/// <b>surface</b> the requirement (return <see cref="ConnectorOutcome.DoubleHopRequired"/>) instead
/// of hanging, unless the caller declared delegation is available and configured on the target. The
/// recommended fix is to push the payload first and run locally (see <see cref="FileTransfer"/>).
/// </summary>
public static partial class DoubleHopDetector
{
    // UNC path: \\server\share (two leading backslashes, then a host, then a share).
    [GeneratedRegex(@"\\\\[A-Za-z0-9._-]+\\[^\s""']+", RegexOptions.CultureInvariant)]
    private static partial Regex UncPath();

    // Onward-session cmdlets that implicitly need delegated credentials.
    //
    // The switch is matched with a lookbehind for a non-word character rather than \b. A word
    // boundary before a hyphen NEVER matches when the hyphen follows whitespace — both are non-word
    // characters, so there is no boundary between them — which meant this pattern could not fire on
    // the ordinary form "New-PSSession -ComputerName dc01" at all. The detection that matters most
    // on WinRM was inert, and silently so: a double-hop would simply not be reported.
    [GeneratedRegex(
        @"\b(New-PSSession|Enter-PSSession|Invoke-Command)\b(?![^\n]*(?<![\w-])-ComputerName\b\s+(localhost|127\.0\.0\.1|\.)(\s|$))[^\n]*(?<![\w-])-ComputerName\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RemoteSession();

    // Mapping a network drive / using an explicit network path.
    [GeneratedRegex(@"\bnet(\.exe)?\s+use\b|\bNew-SmbMapping\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NetworkDrive();

    /// <summary>
    /// Assess a command for an onward-authentication need on <paramref name="protocol"/>.
    ///
    /// <para><b>The pattern scan is Windows-scoped, deliberately.</b> UNC paths,
    /// <c>New-PSSession -ComputerName</c> and <c>net use</c> describe a Windows security model that
    /// has no SSH equivalent: an SSH session that needs a second host just runs another client, with
    /// its own key and no delegation problem. Running these patterns against Linux produced false
    /// positives on commands containing the text incidentally — <c>grep</c> for a UNC-looking string,
    /// a log line mentioning <c>net use</c> — and a false <c>DoubleHopRequired</c> refuses to run a
    /// command that was never going to hop. During a wave that is indistinguishable from a broken
    /// estate.</para>
    ///
    /// <para>The caller's explicit hint is honoured on every protocol: a declared intent to
    /// authenticate onward is a fact about the command, not about Windows.</para>
    /// </summary>
    public static DoubleHopAssessment Assess(RemoteCommand command, EndpointProtocol protocol)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.ExpectsOnwardAuth)
            return new DoubleHopAssessment(true, "Caller declared the command authenticates to a second host.");

        if (protocol != EndpointProtocol.WinRm)
            return DoubleHopAssessment.None;

        var text = command.CommandLine ?? string.Empty;

        if (UncPath().IsMatch(text))
            return new DoubleHopAssessment(true, "Command references a UNC path (\\\\host\\share) requiring onward SMB authentication.");

        if (RemoteSession().IsMatch(text))
            return new DoubleHopAssessment(true, "Command opens a remote PowerShell session to another host, requiring credential delegation.");

        if (NetworkDrive().IsMatch(text))
            return new DoubleHopAssessment(true, "Command maps a network drive, requiring onward SMB authentication.");

        return DoubleHopAssessment.None;
    }

    /// <summary>
    /// Assess a transfer. Push and pull were never assessed at all, yet writing to
    /// <c>\\server\share</c> over a WinRM session is the textbook double-hop — the very case
    /// HARD-PROBLEMS #9 opens with, and the one its recommended fix (push locally, then execute) is
    /// meant to avoid.
    /// </summary>
    public static DoubleHopAssessment Assess(FileTransfer file, EndpointProtocol protocol)
    {
        ArgumentNullException.ThrowIfNull(file);

        if (protocol != EndpointProtocol.WinRm)
            return DoubleHopAssessment.None;

        return UncPath().IsMatch(file.RemotePath ?? string.Empty)
            ? new DoubleHopAssessment(
                true, "Transfer targets a UNC path (\\\\host\\share) requiring onward SMB authentication.")
            : DoubleHopAssessment.None;
    }
}
