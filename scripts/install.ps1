# ==============================================================================
# WireScope Global Installation Script (Windows)
# ==============================================================================

[CmdletBinding()]
param(
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=== Installing WireScope Globally ===" -ForegroundColor Cyan

# 1. Locate or ensure Zig is available
if (-not (Get-Command "zig" -ErrorAction SilentlyContinue)) {
    if (Test-Path "D:\tools\zig-windows-x86_64-0.13.0\zig.exe") {
        $env:Path += ";D:\tools\zig-windows-x86_64-0.13.0"
    } else {
        Write-Error "Zig compiler was not found in PATH or in D:\tools\zig-windows-x86_64-0.13.0. Please install Zig 0.13.0."
        exit 1
    }
}

# 2. Build optimized release binary
Write-Host "Building optimized release binary (ReleaseSafe)..." -ForegroundColor Yellow
zig build -Doptimize=ReleaseSafe
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit 1
}

$SourceBin = Join-Path $PSScriptRoot "..\zig-out\bin\wirescope.exe"
if (-not (Test-Path $SourceBin)) {
    Write-Error "Built binary not found at $SourceBin"
    exit 1
}

# 3. Determine installation target directory
if (-not $TargetDir) {
    if (Test-Path "D:\Antigravity\bin") {
        $TargetDir = "D:\Antigravity\bin"
    } elseif (Test-Path "$env:USERPROFILE\.cargo\bin") {
        $TargetDir = "$env:USERPROFILE\.cargo\bin"
    } else {
        $TargetDir = Join-Path $PSScriptRoot "..\zig-out\bin"
        $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if (-not $UserPath.Contains($TargetDir)) {
            [Environment]::SetEnvironmentVariable("Path", "$UserPath;$TargetDir", "User")
            Write-Host "Added $TargetDir to User PATH." -ForegroundColor Green
        }
    }
}

$DestBin = Join-Path $TargetDir "wirescope.exe"
Copy-Item $SourceBin -Destination $DestBin -Force

Write-Host "[SUCCESS] WireScope installed globally to: $DestBin" -ForegroundColor Green
Write-Host "You can now open any terminal and type: wirescope --help" -ForegroundColor Cyan
