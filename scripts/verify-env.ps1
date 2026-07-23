#requires -Version 7.0
<#
.SYNOPSIS
    Phase 0 environment verifier. Prints a pass/fail table of every prerequisite
    and lab component. Exits non-zero if any REQUIRED check fails.
.NOTES
    Run in PowerShell 7:  pwsh -File scripts/verify-env.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$repoRoot = Split-Path -Parent $PSScriptRoot
$results  = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Check,
        [ValidateSet('PASS','FAIL','WARN')] [string]$Status,
        [string]$Detail = '',
        [bool]$Required = $true
    )
    $results.Add([pscustomobject]@{
        Check    = $Check
        Status   = $Status
        Required = $(if ($Required) { 'yes' } else { 'no' })
        Detail   = $Detail
    })
}

function Test-Command { param([string]$Name) [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

# ---- Toolchain ----
# Resolve dotnet even if PATH wasn't refreshed after a fresh install.
$dotnetExe = 'dotnet'
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    $cand = Join-Path $env:ProgramFiles 'dotnet/dotnet.exe'
    if (Test-Path $cand) { $dotnetExe = $cand }
}
$dotnet = (& $dotnetExe --version) 2>$null
if ($dotnet -and ([version]($dotnet -replace '-.*$')).Major -ge 9) {
    Add-Result '.NET SDK 9+' 'PASS' $dotnet
} else {
    Add-Result '.NET SDK 9+' 'FAIL' ($dotnet ?? 'not found')
}

$node = (& node --version) 2>$null      # e.g. v24.16.0
if ($node -match 'v(\d+)\.') {
    $maj = [int]$Matches[1]
    if ($maj -ge 20 -and ($maj % 2 -eq 0)) { Add-Result 'Node.js (LTS line)' 'PASS' $node }
    else { Add-Result 'Node.js (LTS line)' 'WARN' "$node (not an even/LTS major)" $false }
} else { Add-Result 'Node.js (LTS line)' 'FAIL' 'not found' }

$npm = (& npm --version) 2>$null
Add-Result 'npm' ($(if ($npm) {'PASS'} else {'FAIL'})) ($npm ?? 'not found')

$git = (& git --version) 2>$null
Add-Result 'Git' ($(if ($git) {'PASS'} else {'FAIL'})) ($git ?? 'not found')

Add-Result 'PowerShell 7+' 'PASS' $PSVersionTable.PSVersion.ToString()

$docker = (& docker --version) 2>$null
Add-Result 'Docker' ($(if ($docker) {'PASS'} else {'FAIL'})) ($docker ?? 'not found')

$compose = (& docker compose version) 2>$null | Select-Object -First 1
Add-Result 'Docker Compose' ($(if ($compose) {'PASS'} else {'FAIL'})) ($compose ?? 'not found')

$wsl = (& wsl --status) 2>$null
Add-Result 'WSL2' ($(if ($LASTEXITCODE -eq 0) {'PASS'} else {'WARN'})) 'wsl --status' $false

# ---- Product infra (root stack) ----
function Get-ContainerHealth {
    param([string]$NameLike)
    $id = (& docker ps --filter "name=$NameLike" --format '{{.ID}}') 2>$null | Select-Object -First 1
    if (-not $id) { return 'not-running' }
    $h = (& docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $id) 2>$null
    return ($h ?? 'unknown')
}
$pg = Get-ContainerHealth 'patchmgmt-postgres'
Add-Result 'Postgres (root stack)' ($(if ($pg -in 'healthy','running') {'PASS'} else {'WARN'})) $pg $false
$rd = Get-ContainerHealth 'patchmgmt-redis'
Add-Result 'Redis (root stack)' ($(if ($rd -in 'healthy','running') {'PASS'} else {'WARN'})) $rd $false

# ---- Lab fleet ----
$keyPath = Join-Path $repoRoot 'lab/keys/lab_ed25519'
Add-Result 'Lab SSH key' ($(if (Test-Path $keyPath) {'PASS'} else {'FAIL'})) $keyPath

$fleet = @(
    @{ Name='ubuntu2204'; Port=2201 },
    @{ Name='ubuntu2404'; Port=2202 },
    @{ Name='debian12';   Port=2203 },
    @{ Name='rocky9';     Port=2204 },
    @{ Name='alma9';      Port=2205 }
)
foreach ($h in $fleet) {
    if (-not (Test-Path $keyPath)) { Add-Result "SSH $($h.Name):$($h.Port)" 'FAIL' 'no key' ; continue }
    $out = (& ssh -i $keyPath -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 `
                  -p $h.Port "labadmin@localhost" 'echo ok') 2>$null
    Add-Result "SSH $($h.Name):$($h.Port)" ($(if ($out -match 'ok') {'PASS'} else {'WARN'})) `
               ($(if ($out -match 'ok') {'reachable'} else {'unreachable (is the lab up?)'})) $false
}

# ---- Content ----
$cab = Join-Path $repoRoot 'lab/content/wsusscn2.cab'
if (Test-Path $cab) {
    $mb = [math]::Round((Get-Item $cab).Length / 1MB, 1)
    Add-Result 'wsusscn2.cab' 'PASS' "$mb MB" $false
} else {
    Add-Result 'wsusscn2.cab' 'WARN' 'not downloaded yet' $false
}

# ---- Render ----
Write-Host ''
$results | Format-Table -AutoSize Check, Status, Required, Detail

$failed = @($results | Where-Object { $_.Status -eq 'FAIL' -and $_.Required -eq 'yes' })
Write-Host ''
if ($failed.Count -gt 0) {
    Write-Host "RESULT: $($failed.Count) required check(s) FAILED." -ForegroundColor Red
    exit 1
}
Write-Host 'RESULT: all required checks passed.' -ForegroundColor Green
exit 0
