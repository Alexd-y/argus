<#
.SYNOPSIS
    ARGUS Stage 1 (Intelligence Gathering) + Stage 2 (Threat Modeling) for svalbard.ca

.DESCRIPTION
    Runs both pentest stages and generates combined HTML + PDF report.
    Uses: Docker, AI, MCP. No Cursor Agent.
#>
$ErrorActionPreference = "Stop"
$ARGUS_ROOT = Split-Path -Parent $PSScriptRoot
$RECON_DIR = Join-Path $ARGUS_ROOT "pentest_reports_svalbard\recon\svalbard-stage1"
$REPORTS_DIR = Join-Path $ARGUS_ROOT "pentest_reports_svalbard"
$DOCKER_COMPOSE = Join-Path $ARGUS_ROOT "infra\docker-compose.yml"

Write-Host "=== ARGUS Stage 1 + Stage 2 — svalbard.ca ===" -ForegroundColor Cyan

# 1. Ensure Docker
$containers = docker ps --format "{{.Names}}" 2>$null
if (-not ($containers -match "argus-backend")) {
    Write-Host "[1/5] Starting ARGUS stack..." -ForegroundColor Yellow
    Push-Location $ARGUS_ROOT
    docker compose -f $DOCKER_COMPOSE up -d 2>&1 | Out-Null
    Pop-Location
    Start-Sleep -Seconds 20
} else { Write-Host "[1/5] Backend running" -ForegroundColor Green }

# 2. Stage 1
Write-Host "[2/5] Stage 1 — Intelligence Gathering..." -ForegroundColor Yellow
$stage1Result = python (Join-Path $ARGUS_ROOT "scripts\run_stage1_report.py") 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "  Stage 1 failed: $stage1Result" -ForegroundColor Red; exit 1 }
Write-Host "  Stage 1 OK" -ForegroundColor Green

# 3. Stage 2
Write-Host "[3/5] Stage 2 — Threat Modeling..." -ForegroundColor Yellow
$stage2Result = python (Join-Path $ARGUS_ROOT "scripts\run_stage2_svalbard.py") 2>&1
Write-Host "  $stage2Result" -ForegroundColor Gray

# 4. Combined report
Write-Host "[4/5] Building combined report..." -ForegroundColor Yellow
python (Join-Path $ARGUS_ROOT "scripts\build_combined_report.py") 2>&1 | Out-Null
Write-Host "  OK" -ForegroundColor Green

# 5. PDF
Write-Host "[5/5] Generating PDF..." -ForegroundColor Yellow
$htmlPath = Resolve-Path (Join-Path $REPORTS_DIR "stage1-stage2-svalbard.html")
$pdfPath = Join-Path $REPORTS_DIR "stage1-stage2-svalbard.pdf"
$edge = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
if (Test-Path $edge) {
    & $edge --headless --disable-gpu --print-to-pdf="$pdfPath" "file:///$($htmlPath.Path -replace '\\','/')" 2>$null
}
if (Test-Path $pdfPath) { Write-Host "  PDF: $pdfPath" -ForegroundColor Green } else { Write-Host "  PDF: Open HTML in browser -> Print -> Save as PDF" -ForegroundColor Yellow }

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host "HTML: $REPORTS_DIR\stage1-stage2-svalbard.html"
Write-Host "PDF:  $REPORTS_DIR\stage1-stage2-svalbard.pdf"
