<#
.SYNOPSIS
    ARGUS Stage 1 Intelligence Gathering Orchestrator
    
.DESCRIPTION
    Полностью автоматизированный цикл Stage 1 разведки:
    1. Проверка инфраструктуры (Docker, backend)
    2. Инициализация MCP для интеграции с LLM agents
    3. Запуск Stage 1 разведки (passive intel gathering)
    4. Генерация HTML + PDF отчётов
    
    Используется:
    - Контейнеризация (Docker) для backend/infra
    - AI анализ (если LLM ключи установлены в backend/.env)
    - MCP для интеграции с Cursor/Claude agents
    - Intel адаптеры (Shodan, GitHub, Censys, SecurityTrails, VirusTotal, AbuseIPDB, GreyNoise, OTX, URLscan, ExploitDB)
    - Stage 1 resources (NVD, crt.sh, RDAP, DNS)

.NOTES
    Логирование: JSON format для парсирования
    Ошибки: Никогда не выводим стэки (информационная утечка)
    Timeouts: Docker 30s, MCP 10s, HTTP 300s
    
.EXAMPLE
    .\scripts\run-stage1-recon-svalbard.ps1
    
.LINK
    Документация: scripts/README.md
#>

param(
    [switch]$Fast  # Быстрая генерация отчёта: --fast (без сетевых запросов endpoint/headers, без intel)
)
$ErrorActionPreference = "Stop"
$ARGUS_ROOT = Split-Path -Parent $PSScriptRoot
$BACKEND = Join-Path $ARGUS_ROOT "backend"
$RECON_DIR = Join-Path $ARGUS_ROOT "pentest_reports_svalbard\recon\svalbard-stage1"
$REPORTS_DIR = Join-Path $ARGUS_ROOT "pentest_reports_svalbard"
$DOCKER_COMPOSE = Join-Path $ARGUS_ROOT "infra\docker-compose.yml"

Write-Host "=== ARGUS Stage 1 Intelligence Gathering — svalbard.ca ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Инфраструктурная проверка
# Убедимся, что ARGUS backend запущен в контейнере (или уже работает)
# Статус: ИНИЦИАЛИЗАЦИЯ ИНФРАСТРУКТУРЫ
Write-Host "[1/6] Checking Docker containers..." -ForegroundColor Yellow
$containers = docker ps --format "{{.Names}}" 2>$null
$backendUp = $containers -match "argus-backend"
if (-not $backendUp) {
    Write-Host "  Starting ARGUS stack..." -ForegroundColor Gray
    Push-Location $ARGUS_ROOT
    docker compose -f $DOCKER_COMPOSE up -d 2>&1 | Out-Null
    Pop-Location
    Write-Host "  Waiting for backend to be ready..." -ForegroundColor Gray
    Start-Sleep -Seconds 30
} else {
    Write-Host "  Backend already running." -ForegroundColor Green
}

# Step 2: Проверка здоровья backend
# Убедимся, что API доступен (/api/v1/health endpoint)
# Если backend недоступен — отчёт будет сгенерирован локально (без backend)
Write-Host "[2/6] Verifying backend health..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/health" -Method Get -TimeoutSec 5
    Write-Host "  Backend OK: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host '  WARNING: Backend not reachable. Report generation will run locally.' -ForegroundColor Yellow
}

# Step 3: Инициализация MCP сервера
# MCP (Model Context Protocol) обеспечивает интеграцию Stage 1 с LLM agents (Cursor, Claude)
# При use_mcp=True: используется MCP для HTTP fetch (с поддержкой agent-driven actions)
# При use_mcp=False: используется встроенный httpx для HTTP запросов
# Fallback: если MCP недоступен, автоматически переходим на httpx
Write-Host "[3/6] Ensuring MCP availability..." -ForegroundColor Yellow
$scriptDir = Join-Path $ARGUS_ROOT "scripts"
& (Join-Path $scriptDir "ensure_mcp_server.ps1")

# Step 4: Генерация Stage 1 отчёта
# Core logic: passive reconnaissance pipeline (Stage 0-4)
# 
# Параметры:
#   use_mcp=True           → Использовать MCP для HTTP fetch (преимущество: интеграция с agents)
#   use_ai=True (if key)   → Включить AI анализ аномалий/гипотез (требует LLM ключ)
#   use_intel=True (по умолч.) → Включить Intel адаптеры (Shodan, GitHub, etc.)
#
# Бесплатные ресурсы (встроено):
#   - DNS records (A/AAAA/MX/TXT)
#   - SSL certificates (crt.sh)
#   - WHOIS/RDAP (IP ownership)
#   - NVD (CVE lookup)
#   - HTTP probing (safe, passive)
#
# Платные/доп. ресурсы (если ключи установлены):
#   - Shodan (SHODAN_API_KEY)
#   - GitHub (GITHUB_TOKEN)
#   - Censys (CENSYS_API_KEY)
#   - SecurityTrails (SECURITYTRAILS_API_KEY)
#   - VirusTotal (VIRUSTOTAL_API_KEY)
#   - AbuseIPDB (ABUSEIPDB_API_KEY)
#   - GreyNoise (GREYNOISE_API_KEY)
#   - OTX (OTX_API_KEY)
#   - URLscan (URLSCAN_API_KEY)
#   - ExploitDB (EXPLOITDB_API_KEY)
$reportArgs = @()
if ($Fast) { $reportArgs += "--fast"; Write-Host "  Using --fast mode (no network calls for endpoints/headers)" -ForegroundColor Gray }
Write-Host "[4/6] Generating Stage 1 report (ARGUS pipeline, use_mcp=$(if ($Fast) { 'false' } else { 'true' }))..." -ForegroundColor Yellow
$reportResult = python (Join-Path $scriptDir "run_stage1_report.py") @reportArgs 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Report generation failed:" -ForegroundColor Red
    Write-Host $reportResult
    exit 1
}
Write-Host "  $reportResult" -ForegroundColor Green

# 5. Копирование HTML в папку отчётов
$stage1Html = Join-Path $RECON_DIR "stage1_report.html"
$outputHtml = Join-Path $REPORTS_DIR "stage1-svalbard.html"
if (Test-Path $stage1Html) {
    Copy-Item $stage1Html $outputHtml -Force
    # Step 5: Копирование HTML отчёта в публичную папку
# Исходник: pentest_reports_svalbard/recon/svalbard-stage1/stage1_report.html
# Целевая папка: pentest_reports_svalbard/stage1-svalbard.html (для пользователя)
Write-Host "[5/6] Report copied to $outputHtml" -ForegroundColor Green
} else {
    Write-Host "  WARNING: stage1_report.html not found in recon dir." -ForegroundColor Yellow
}

# Step 6: Генерация PDF (опционально)
# Если существует generate-pdf.ps1 — используем его для создания PDF из HTML
# Иначе: пользователь открывает HTML в браузере и печатает как PDF
Write-Host "[6/6] Generating PDF..." -ForegroundColor Yellow
$pdfScript = Join-Path $REPORTS_DIR "generate-pdf.ps1"
if (Test-Path $pdfScript) {
    & $pdfScript -baseName "stage1-svalbard"
    if (Test-Path (Join-Path $REPORTS_DIR "stage1-svalbard.pdf")) {
        Write-Host "  PDF created: pentest_reports_svalbard\stage1-svalbard.pdf" -ForegroundColor Green
    }
} else {
    Write-Host "  To create PDF: Open stage1-svalbard.html in browser -> Print -> Save as PDF" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host "HTML: $outputHtml"
Write-Host "PDF:  $REPORTS_DIR\stage1-svalbard.pdf"
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Методология: ARGUS Recon Pipeline (Stages 0-4). Passive + безопасное HTTP probing." -ForegroundColor Gray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "🤖 AI Orchestrator:" -ForegroundColor Cyan
Write-Host "   Включена анализ аномалий/гипотез когда установлена LLM ключ в backend/.env" -ForegroundColor Gray
Write-Host "   Поддерживаемые LLM: OpenAI, DeepSeek, OpenRouter, Google, Kimi, Perplexity" -ForegroundColor Gray
Write-Host ""
Write-Host "🔌 MCP Server:" -ForegroundColor Cyan
Write-Host "   Endpoint discovery использует MCP когда доступен (use_mcp=True)" -ForegroundColor Gray
Write-Host "   Fallback: встроенный httpx для HTTP запросов если MCP недоступен" -ForegroundColor Gray
Write-Host ""
Write-Host "📊 Intel Adapters:" -ForegroundColor Cyan
Write-Host "   Shodan, GitHub, Censys, SecurityTrails, VirusTotal, AbuseIPDB, GreyNoise, OTX, URLscan, ExploitDB" -ForegroundColor Gray
Write-Host "   Каждый адаптер опционален; включается только если ключ установлен в backend/.env" -ForegroundColor Gray
Write-Host ""
Write-Host "📚 Документация: d:\Developer\Pentest_test\ARGUS\scripts\README.md" -ForegroundColor Cyan
Write-Host ""
