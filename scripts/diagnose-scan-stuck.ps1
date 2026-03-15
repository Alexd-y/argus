# ARGUS: Диагностика "Скан застрял на Initializing"
# Запуск: .\scripts\diagnose-scan-stuck.ps1

$BackendUrl = if ($env:NEXT_PUBLIC_BACKEND_URL) { $env:NEXT_PUBLIC_BACKEND_URL } else { "http://localhost:5000" }
$ApiBase = "$BackendUrl/api/v1"

Write-Host "=== ARGUS Scan Diagnostics ===" -ForegroundColor Cyan
Write-Host "Backend: $ApiBase" -ForegroundColor Gray
Write-Host ""

# 1. Health
Write-Host "[1] Backend Health (GET /health)" -ForegroundColor Yellow
try {
    $r = Invoke-RestMethod -Uri "$ApiBase/health" -Method Get -TimeoutSec 5
    Write-Host "  OK: status=$($r.status), version=$($r.version)" -ForegroundColor Green
} catch {
    Write-Host "  FAIL: Backend not reachable. Is it running?" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Readiness (DB, Redis, MinIO)
Write-Host ""
Write-Host "[2] Backend Readiness (GET /ready)" -ForegroundColor Yellow
try {
    $r = Invoke-RestMethod -Uri "$ApiBase/ready" -Method Get -TimeoutSec 5
    $db = if ($r.database) { "OK" } else { "FAIL" }
    $redis = if ($r.redis) { "OK" } else { "FAIL" }
    $storage = if ($r.storage) { "OK" } else { "FAIL" }
    Write-Host "  DB: $db | Redis: $redis | Storage: $storage | status=$($r.status)" -ForegroundColor $(if ($r.status -eq "ok") { "Green" } else { "Yellow" })
} catch {
    Write-Host "  FAIL: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Celery process
Write-Host ""
Write-Host "[3] Celery Worker Process" -ForegroundColor Yellow
$celery = Get-Process -Name celery -ErrorAction SilentlyContinue
if ($celery) {
    Write-Host "  OK: Celery process(es) running (PID: $($celery.Id -join ', '))" -ForegroundColor Green
} else {
    Write-Host "  WARN: No Celery process found. Scans will stay at 0% until worker is started." -ForegroundColor Red
    Write-Host "  Run: celery -A src.celery_app worker -l INFO -Q argus.scans,argus.reports,argus.tools,argus.default" -ForegroundColor Gray
}

# 4. Redis (optional, if redis-cli available)
Write-Host ""
Write-Host "[4] Redis (redis-cli ping)" -ForegroundColor Yellow
$redisCli = Get-Command redis-cli -ErrorAction SilentlyContinue
if ($redisCli) {
    try {
        $ping = & redis-cli ping 2>$null
        if ($ping -eq "PONG") {
            Write-Host "  OK: Redis responding" -ForegroundColor Green
        } else {
            Write-Host "  WARN: Redis returned: $ping" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  WARN: redis-cli failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  SKIP: redis-cli not in PATH" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "If Celery is not running, start it from ARGUS/backend directory." -ForegroundColor White
Write-Host "See docs/diagnostics-scan-stuck-initializing.md for details." -ForegroundColor Gray
