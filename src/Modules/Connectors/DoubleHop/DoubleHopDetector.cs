using System.Text.RegularExpressions;
using PatchManagement.Connectors.Model;

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
    [GeneratedRegex(
        @"\b(New-PSSession|Enter-PSSession|Invoke-Command)\b(?![^\n]*\b-ComputerName\b\s+(localhost|127\.0\.0\.1|\.)\b)[^\n]*\b-ComputerName\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RemoteSession();

    // Mapping a network drive / using an explicit network path.
    [GeneratedRegex(@"\bnet(\.exe)?\s+use\b|\bNew-SmbMapping\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NetworkDrive();

    public static DoubleHopAssessment Assess(RemoteCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.ExpectsOnwardAuth)
            return new DoubleHopAssessment(true, "Caller declared the command authenticates to a second host.");

        var text = command.CommandLine ?? string.Empty;

        if (UncPath().IsMatch(text))
            return new DoubleHopAssessment(true, "Command references a UNC path (\\\\host\\share) requiring onward SMB authentication.");

        if (RemoteSession().IsMatch(text))
            return new DoubleHopAssessment(true, "Command opens a remote PowerShell session to another host, requiring credential delegation.");

        if (NetworkDrive().IsMatch(text))
            return new DoubleHopAssessment(true, "Command maps a network drive, requiring onward SMB authentication.");

        return DoubleHopAssessment.None;
    }
}
