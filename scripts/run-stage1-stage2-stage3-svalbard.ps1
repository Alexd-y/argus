<#
.SYNOPSIS
    ARGUS Stage 1 + 2 + 3 — svalbard.ca (Intelligence Gathering, Threat Modeling, Vulnerability Analysis)

.DESCRIPTION
    Runs all three pentest stages and generates combined HTML + PDF report.
    Uses: Docker, AI, MCP. No Cursor Agent.
#>
$ErrorActionPreference = "Stop"
$ARGUS_ROOT = Split-Path -Parent $PSScriptRoot
$RECON_DIR = Join-Path $ARGUS_ROOT "pentest_reports_svalbard\recon\svalbard-stage1"
$REPORTS_DIR = Join-Path $ARGUS_ROOT "pentest_reports_svalbard"
$DOCKER_COMPOSE = Join-Path $ARGUS_ROOT "infra\docker-compose.yml"

Write-Host "=== ARGUS Stage 1 + 2 + 3 — svalbard.ca ===" -ForegroundColor Cyan

# 1. Ensure Docker
$containers = docker ps --format "{{.Names}}" 2>$null
if (-not ($containers -match "argus-backend")) {
    Write-Host "[1/7] Starting ARGUS stack..." -ForegroundColor Yellow
    Push-Location $ARGUS_ROOT
    docker compose -f $DOCKER_COMPOSE up -d 2>&1 | Out-Null
    Pop-Location
    Start-Sleep -Seconds 20
} else { Write-Host "[1/7] Backend running" -ForegroundColor Green }

# 2. Stage 1
Write-Host "[2/7] Stage 1 — Intelligence Gathering..." -ForegroundColor Yellow
$stage1Result = python (Join-Path $ARGUS_ROOT "scripts\run_stage1_report.py") 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "  Stage 1 failed: $stage1Result" -ForegroundColor Red; exit 1 }
Write-Host "  Stage 1 OK" -ForegroundColor Green

# 3. Stage 3 prep (route_classification, stage3_readiness)
Write-Host "[3/7] Preparing Stage 3 artifacts..." -ForegroundColor Yellow
python (Join-Path $ARGUS_ROOT "scripts\prepare_stage3_artifacts.py") 2>&1 | Out-Null
Write-Host "  OK" -ForegroundColor Green

# 4. Stage 2
Write-Host "[4/7] Stage 2 — Threat Modeling..." -ForegroundColor Yellow
$stage2Result = python (Join-Path $ARGUS_ROOT "scripts\run_stage2_svalbard.py") 2>&1
Write-Host "  $stage2Result" -ForegroundColor Gray

# 5. Stage 3
Write-Host "[5/7] Stage 3 — Vulnerability Analysis..." -ForegroundColor Yellow
$stage3Result = python (Join-Path $ARGUS_ROOT "scripts\run_stage3_svalbard.py") 2>&1
Write-Host "  $stage3Result" -ForegroundColor Gray

# 6. Combined report
Write-Host "[6/7] Building combined report..." -ForegroundColor Yellow
python (Join-Path $ARGUS_ROOT "scripts\build_combined_report.py") 2>&1 | Out-Null
Write-Host "  OK" -ForegroundColor Green

# 7. PDF
Write-Host "[7/7] Generating PDF..." -ForegroundColor Yellow
$htmlPath = Resolve-Path (Join-Path $REPORTS_DIR "stage1-stage2-stage3-svalbard.html")
$pdfPath = Join-Path $REPORTS_DIR "stage1-stage2-stage3-svalbard.pdf"
$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path $edge)) { $edge = "C:\Program Files\Microsoft\Edge\Application\msedge.exe" }
if (Test-Path $edge) {
    & $edge --headless --disable-gpu --print-to-pdf="$pdfPath" "file:///$($htmlPath.Path -replace '\\','/')" 2>$null
}
if (Test-Path $pdfPath) { Write-Host "  PDF: $pdfPath" -ForegroundColor Green } else { Write-Host "  PDF: Open HTML in browser -> Print -> Save as PDF" -ForegroundColor Yellow }

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host "HTML: $REPORTS_DIR\stage1-stage2-stage3-svalbard.html"
Write-Host "PDF:  $REPORTS_DIR\stage1-stage2-stage3-svalbard.pdf"
