# ==============================================================================
# WireScope Safety Gate Verification (PowerShell / Windows)
#
# Verifies that non-interactive mode strictly enforces authorization gates
# and does not bypass safety limits on remote targets.
# ==============================================================================

param (
    [string]$WirescopeBin = "wirescope",
    [string]$RemoteTarget = "192.168.1.100"
)

$ErrorActionPreference = "Continue"

Write-Host "=== Test 1: Remote target in non-interactive mode without confirmation ===" -ForegroundColor Cyan
& $WirescopeBin discover $RemoteTarget --preview --non-interactive 2> error.log
$ExitCode = $LASTEXITCODE

if ($ExitCode -eq 2) {
    Write-Host "[SUCCESS] Safety gate held! WireScope exited with code 2 (invalid_input)." -ForegroundColor Green
    Get-Content error.log
} else {
    Write-Host "[FAILURE] Expected exit code 2, got $ExitCode" -ForegroundColor Red
    exit 1
}

Write-Host "=== Test 2: Remote target with explicit --confirm-authorized ===" -ForegroundColor Cyan
& $WirescopeBin discover $RemoteTarget --preview --confirm-authorized --non-interactive --format json 1> plan.json
$ExitCode2 = $LASTEXITCODE

if ($ExitCode2 -eq 0) {
    Write-Host "[SUCCESS] Explicitly authorized plan generated successfully without prompts!" -ForegroundColor Green
} else {
    Write-Host "[FAILURE] Expected exit code 0, got $ExitCode2" -ForegroundColor Red
    exit 1
}
