<#
.SYNOPSIS
    Fails if a stale test host is still running, which would make a test run report on code that is
    no longer on disk.

.DESCRIPTION
    A `dotnet test` that is killed, backgrounded or timed out can leave `testhost` alive holding a
    lock on the output assemblies. The next build then CANNOT overwrite them — MSBuild reports
    MSB3026 as a *warning*, the build still says "Build succeeded", and the run executes the previous
    binaries. The suite reports green (or red) for source that is not what you just edited.

    That already happened here once: a comment-filter fix was verifiably present in the source and
    the scan kept failing, because the assembly under test was the older copy. It is the build-layer
    form of this project's characteristic failure — reporting success while untrue — and it is worse
    than a normal flake because both the pass and the fail are untrustworthy.

    Run this before `dotnet test`. It refuses to proceed rather than warning, because a warning in a
    wall of build output is exactly what was missed the first time.

.PARAMETER Kill
    Terminate the offending processes instead of failing.

.EXAMPLE
    pwsh scripts/test-preflight.ps1
    pwsh scripts/test-preflight.ps1 -Kill
#>
[CmdletBinding()]
param([switch]$Kill)

$ErrorActionPreference = 'Stop'

$stale = @(Get-Process -Name 'testhost', 'testhost.x86', 'vstest.console' -ErrorAction SilentlyContinue)

if ($stale.Count -eq 0) {
    Write-Host 'test-preflight: no stale test host processes.' -ForegroundColor Green
    exit 0
}

$detail = ($stale | ForEach-Object { "  $($_.ProcessName) (PID $($_.Id)), started $($_.StartTime)" }) -join [Environment]::NewLine

if ($Kill) {
    Write-Host "test-preflight: terminating $($stale.Count) stale test host process(es):" -ForegroundColor Yellow
    Write-Host $detail
    $stale | Stop-Process -Force
    Start-Sleep -Milliseconds 300
    Write-Host 'test-preflight: cleared.' -ForegroundColor Green
    exit 0
}

Write-Error @"
test-preflight: $($stale.Count) stale test host process(es) are still running.

$detail

They hold locks on the test output assemblies, so the next build cannot replace them. MSBuild
downgrades that to an MSB3026 warning and still prints "Build succeeded", and the run then executes
STALE BINARIES — the results describe code that is not on disk.

Clear them and re-run:
  pwsh scripts/test-preflight.ps1 -Kill
"@
exit 1
