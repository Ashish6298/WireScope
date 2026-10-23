# ==============================================================================
# WireScope Assessment & Reporting Pipeline for Explicitly Authorized Targets
# (PowerShell / Windows Automation)
# ==============================================================================

param (
    [string]$WirescopeBin = "wirescope",
    [string]$ReportJson = "examples/assessment_report.json"
)

$ErrorActionPreference = "Stop"
$ReportMd = "assessment_summary.md"

Write-Host "=== 1. Validating Versioned Report Against Schema ($ReportJson) ===" -ForegroundColor Cyan
& $WirescopeBin report validate $ReportJson
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Report validation failed with code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "[PASS] Report validated against versioned schema." -ForegroundColor Green

Write-Host "=== 2. Exporting Markdown Report (Safe Atomic Write) ===" -ForegroundColor Cyan
& $WirescopeBin report markdown $ReportJson --output $ReportMd --force --non-interactive
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Markdown report export failed with code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "=== Pipeline Complete: Generated $ReportMd successfully ===" -ForegroundColor Green
exit 0
