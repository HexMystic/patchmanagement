<#
.SYNOPSIS
    Refuses to proceed unless a mutation actually landed in the source.

.DESCRIPTION
    A mutation check is only evidence if the code really changed. A scripted patch that silently
    fails to match reports success, the suite runs against UNMODIFIED source, and the result reads
    exactly like "the test could not catch this" — or worse, like "the fix was not load-bearing".

    That has now happened three times in this phase (T7's regex revert, T8's log probe, T6.5's
    diagnostic patch), which makes it a tooling hazard rather than carelessness. So the check is
    mechanical: chain it before the test run and the run cannot happen on unmutated source.

        pwsh scripts/mutation-guard.ps1 -Path src/... -Marker "MUTATION PROBE 5" ; if ($?) { dotnet test ... }

    It verifies BOTH that git sees the file as modified and that the marker is present, because
    either alone can lie: a marker can be added by an edit that was reverted elsewhere, and a diff
    can be non-empty for unrelated reasons.

.PARAMETER Path
    Source file the mutation was applied to.

.PARAMETER Marker
    Text the mutation must have introduced.

.PARAMETER Absent
    Invert: assert the marker is GONE and the file is clean again (use after reverting).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Marker,
    [switch]$Absent
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Path)) { Write-Error "mutation-guard: '$Path' does not exist."; exit 1 }

$content = Get-Content -Raw -LiteralPath $Path
$hasMarker = $content.Contains($Marker)
$diff = (& git diff --name-only -- $Path) -join ''
$isDirty = -not [string]::IsNullOrWhiteSpace($diff)

if ($Absent) {
    if ($hasMarker) {
        Write-Error "mutation-guard: marker '$Marker' is STILL PRESENT in $Path — the revert did not land."
        exit 1
    }
    if ($isDirty) {
        Write-Warning "mutation-guard: $Path still differs from HEAD (may be intentional):"
        & git diff --stat -- $Path
    }
    Write-Host "mutation-guard: revert confirmed — marker absent from $Path." -ForegroundColor Green
    exit 0
}

if (-not $hasMarker) {
    Write-Error @"
mutation-guard: marker '$Marker' NOT FOUND in $Path.

The mutation did not land. Running the suite now would test UNMODIFIED source and the green/red
result would describe code that is not the code you think you are testing.
"@
    exit 1
}

if (-not $isDirty) {
    Write-Error "mutation-guard: $Path matches HEAD despite containing the marker — nothing was mutated."
    exit 1
}

Write-Host "mutation-guard: mutation confirmed in $Path" -ForegroundColor Yellow
& git diff --stat -- $Path
& git diff -- $Path | Select-String -Pattern '^[+-][^+-]' | Select-Object -First 12 | ForEach-Object { $_.Line }
exit 0
