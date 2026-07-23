#requires -Version 5.1
<#
.SYNOPSIS
    Generate the ed25519 keypair used to authenticate to the Linux lab fleet.
.DESCRIPTION
    Creates lab/keys/lab_ed25519(.pub) if not already present. The public key is
    mounted read-only into every lab container by lab/docker-compose.yml. The
    private key is gitignored and NEVER committed.
#>
[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$keyDir   = Join-Path $repoRoot 'lab/keys'
$keyPath  = Join-Path $keyDir  'lab_ed25519'

New-Item -ItemType Directory -Force -Path $keyDir | Out-Null

if ((Test-Path $keyPath) -and -not $Force) {
    Write-Host "Key already exists: $keyPath (use -Force to regenerate)" -ForegroundColor Yellow
    exit 0
}

if (Test-Path $keyPath) { Remove-Item "$keyPath","$keyPath.pub" -Force -ErrorAction SilentlyContinue }

$ssh = (Get-Command ssh-keygen -ErrorAction SilentlyContinue)
if (-not $ssh) { throw "ssh-keygen not found. Install OpenSSH client (it ships with Git for Windows)." }

# Windows PowerShell 5.1 drops empty-string args ('') when calling native exes,
# so `-N ''` for "no passphrase" fails. Use the stop-parsing token (--%) with a
# cmd-style env var for the path (expanded as %KG_OUT%); this works on PS 5.1 and 7.
$env:KG_OUT = $keyPath
ssh-keygen --% -t ed25519 -N "" -C patchmgmt-lab -f %KG_OUT%
$code = $LASTEXITCODE
Remove-Item Env:KG_OUT -ErrorAction SilentlyContinue
if ($code -ne 0) { throw "ssh-keygen failed with exit code $code" }

Write-Host "Generated keypair:" -ForegroundColor Green
Write-Host "  private: $keyPath  (gitignored)"
Write-Host "  public : $keyPath.pub"
