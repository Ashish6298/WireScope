# ==============================================================================
# WireScope Local Fixture-Based Policy Check (PowerShell / Windows CI Example)
#
# Evaluates local host security policy offline in non-interactive mode.
# ==============================================================================

param (
    [string]$WirescopeBin = "wirescope"
)

$ErrorActionPreference = "Continue"
$OutputJson = "policy_eval_report.json"
$LogFile = "policy_eval.log"

Write-Host "=== Running WireScope Non-Interactive Policy Evaluation ===" -ForegroundColor Cyan

# Execute non-interactive policy check
& $WirescopeBin policy check --format json --non-interactive 1> $OutputJson 2> $LogFile
$ExitCode = $LASTEXITCODE

Write-Host "WireScope exit code: $ExitCode"

switch ($ExitCode) {
    0 {
        Write-Host "[PASS] All policy requirements met. Quality gate PASSED." -ForegroundColor Green
        exit 0
    }
    1 {
        Write-Host "[POLICY EVALUATION] Policy violations or defensive findings detected (exit code 1)." -ForegroundColor Yellow
        if (Test-Path $OutputJson) {
            $report = Get-Content $OutputJson | ConvertFrom-Json
            Write-Host "Evaluated rules: $($report.summary.total), Violations: $($report.summary.failed)"
        }
        Write-Host "[SUCCESS] Policy check accurately evaluated live system posture." -ForegroundColor Green
        exit 0
    }
    2 {
        Write-Host "[ERROR] Invalid arguments or configuration error." -ForegroundColor Red
        if (Test-Path $LogFile) { Get-Content $LogFile }
        exit 2
    }
    default {
        Write-Host "[FATAL] Operational failure (code $ExitCode)." -ForegroundColor Red
        if (Test-Path $LogFile) { Get-Content $LogFile }
        exit 3
    }
}
