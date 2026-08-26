using PatchManagement.Contracts.Connectors;

namespace PatchManagement.Connectors.Facts;

/// <summary>
/// Gathers basic inventory facts (OS identity + installed packages) from a Linux endpoint by
/// running bounded commands through any <see cref="IEndpointConnector"/>. It detects the package
/// manager present (dpkg vs rpm) and queries accordingly, so one collector serves the whole lab
/// fleet. Every command is time-bounded; a failed probe is surfaced honestly, never guessed.
/// </summary>
public sealed class EndpointFactsCollector
{
    private readonly IEndpointConnector _connector;

    public EndpointFactsCollector(IEndpointConnector connector) => _connector = connector;

    public async Task<EndpointFacts> CollectAsync(EndpointTarget target, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        var timeout = TimeSpan.FromSeconds(30);

        var os = await RunOrThrow(target, ". /etc/os-release; echo \"$ID|$VERSION_ID\"", timeout, ct).ConfigureAwait(false);
        var (osId, osVersion) = LinuxFactsParser.ParseOsRelease(os);

        var arch = (await RunOrThrow(target, "uname -m", timeout, ct).ConfigureAwait(false)).Trim();

        // Prefer dpkg; fall back to rpm. `command -v` keeps this a single bounded round-trip decision.
        var hasDpkg = await CommandSucceeds(target, "command -v dpkg-query", timeout, ct).ConfigureAwait(false);
        if (hasDpkg)
        {
            var listing = await RunOrThrow(target, @"dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'", timeout, ct).ConfigureAwait(false);
            return Build("debian", osId, osVersion, arch, "dpkg", LinuxFactsParser.ParseDpkg(listing));
        }

        // The EPOCH is emitted, conditionally, and omitting it was a real defect: asset_packages.epoch
        // exists precisely because the epoch DOMINATES version comparison (HARD-PROBLEMS #3), and this
        // query asked only for VERSION-RELEASE — so every RPM epoch was lost between a host that knows
        // it and a column built to hold it, silently, with the column simply staying null.
        //
        // %|EPOCH?{...}| is rpm's conditional format: it emits "N:" only where an epoch is set, rather
        // than the literal "(none)" a bare %{EPOCH} yields for the majority of packages. dpkg needs no
        // equivalent change — its ${Version} already carries the epoch.
        var rpmListing = await RunOrThrow(target, @"rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{ARCH}\n'", timeout, ct).ConfigureAwait(false);
        return Build("rhel", osId, osVersion, arch, "rpm", LinuxFactsParser.ParseRpm(rpmListing));
    }

    private static EndpointFacts Build(
        string family, string osId, string osVersion, string arch, string pm, IReadOnlyList<InstalledPackage> packages) => new()
    {
        OsFamily = family,
        OsId = osId,
        OsVersion = osVersion,
        Architecture = arch,
        PackageManager = pm,
        Packages = packages,
    };

    private async Task<bool> CommandSucceeds(EndpointTarget target, string command, TimeSpan timeout, CancellationToken ct)
    {
        var result = await _connector.RunAsync(target, new RemoteCommand { CommandLine = command, Timeout = timeout }, ct).ConfigureAwait(false);
        return result.Succeeded && result.ExitCode == 0;
    }

    private async Task<string> RunOrThrow(EndpointTarget target, string command, TimeSpan timeout, CancellationToken ct)
    {
        var result = await _connector.RunAsync(target, new RemoteCommand { CommandLine = command, Timeout = timeout }, ct).ConfigureAwait(false);
        // Bounded codes plus the outcome/exit code — never the command text or the remote detail.
        // The command line is where a caller embeds a secret, and result.Detail may itself have been
        // built from remote output. Interpolating either here would push both into an exception
        // message that ASP.NET logs outside any redaction scope (ADR 0012's residual for Phase 3).
        if (!result.Succeeded)
            throw new FactsCollectionException($"{ConnectorReason.FactsCommandFailed} ({result.Outcome})");
        if (result.ExitCode != 0)
            throw new FactsCollectionException($"{ConnectorReason.FactsCommandNonZeroExit} (exit {result.ExitCode})");
        return result.StandardOutput;
    }
}

/// <summary>Raised when a required fact-gathering command could not be completed honestly.</summary>
public sealed class FactsCollectionException(string message) : Exception(message);
