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
        Write-Host "[FAIL] Policy violations detected. Quality gate FAILED." -ForegroundColor Yellow
        if (Test-Path $OutputJson) {
            $report = Get-Content $OutputJson | ConvertFrom-Json
            Write-Host "Evaluated rules: $($report.total_rules_evaluated), Violations: $($report.failed_count)"
        }
        exit 1
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
