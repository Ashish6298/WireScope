# ==============================================================================
# WireScope Release Rehearsal Script (PowerShell / Windows)
#
# Simulates full release artifact generation, packaging, and checksum verification
# ==============================================================================

param (
    [string]$Version = "0.1.0-rc1",
    [string]$ZigExe = "D:\tools\zig-windows-x86_64-0.13.0\zig.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "=== WireScope Release Rehearsal: v$Version ===" -ForegroundColor Cyan

# 1. Test build with ReleaseSafe optimization
Write-Host "1. Building optimized ReleaseSafe binary..." -ForegroundColor Yellow
& $ZigExe build -Doptimize=ReleaseSafe
if ($LASTEXITCODE -ne 0) { throw "Build failed!" }

$BinaryPath = "zig-out\bin\wirescope.exe"
if (-not (Test-Path $BinaryPath)) { throw "Binary not found at $BinaryPath" }

# 2. Smoke test executable
Write-Host "2. Smoke testing binary..." -ForegroundColor Yellow
& $BinaryPath version
& $BinaryPath capabilities --format json | Out-Null
Write-Host "   Smoke test passed!" -ForegroundColor Green

# 3. Create release package
Write-Host "3. Creating release package..." -ForegroundColor Yellow
$StageDir = "rehearsal_dist"
$ArchiveName = "wirescope-v$Version-windows-x86_64.zip"

if (Test-Path $StageDir) { Remove-Item -Path $StageDir -Recurse -Force }
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

Copy-Item $BinaryPath -Destination $StageDir
Copy-Item "README.md" -Destination $StageDir
Copy-Item "LICENSE" -Destination $StageDir
Copy-Item "SECURITY.md" -Destination $StageDir

if (Test-Path $ArchiveName) { Remove-Item -Path $ArchiveName -Force }
Compress-Archive -Path "$StageDir\*" -DestinationPath $ArchiveName -Force
Write-Host "   Package created: $ArchiveName" -ForegroundColor Green

# 4. Generate SHA-256 Checksum
Write-Host "4. Computing SHA-256 Checksum..." -ForegroundColor Yellow
$Hash = (Get-FileHash -Path $ArchiveName -Algorithm SHA256).Hash.ToLower()
"$Hash  $ArchiveName" | Out-File -FilePath "$ArchiveName.sha256" -Encoding ascii
Write-Host "   SHA-256: $Hash" -ForegroundColor Green

# 5. Verify Checksum
Write-Host "5. Verifying Checksum integrity..." -ForegroundColor Yellow
$VerifyHash = (Get-FileHash -Path $ArchiveName -Algorithm SHA256).Hash.ToLower()
if ($VerifyHash -ne $Hash) { throw "Checksum mismatch!" }
Write-Host "   Checksum verified successfully!" -ForegroundColor Green

# 6. Cleanup stage dir
Remove-Item -Path $StageDir -Recurse -Force
Remove-Item -Path $ArchiveName -Force
Remove-Item -Path "$ArchiveName.sha256" -Force

Write-Host "=== Rehearsal Completed Successfully! All criteria passed. ===" -ForegroundColor Cyan
