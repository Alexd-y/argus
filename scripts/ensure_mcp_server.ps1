# ARGUS MCP Server — ensure MCP is available before report generation
# - mcp-server-fetch (pip): endpoint discovery for Stage 1 (robots.txt, sitemap, etc.); fallback to httpx if unavailable
# - ARGUS MCP (argus-mcp container): Cursor/agent tools (create_scan, subfinder, httpx); stdio-only, not used by backend
# Usage: .\scripts\ensure_mcp_server.ps1

$ErrorActionPreference = "Continue"
$ARGUS_ROOT = Split-Path -Parent $PSScriptRoot
$COMPOSE_FILE = Join-Path $ARGUS_ROOT "infra\docker-compose.yml"

function Test-ArgusMcpRunning {
    $names = docker ps --format "{{.Names}}" 2>$null
    return $names -match "argus-mcp"
}

Write-Host "[MCP] Checking MCP availability..." -ForegroundColor Gray

# 1. Check mcp-server-fetch (used by endpoint_builder for robots.txt, sitemap, etc.)
$mcpFetch = python -c "
try:
    import mcp_server_fetch
    print('ok')
except ImportError:
    print('missing')
" 2>$null

if ($mcpFetch -eq "ok") {
    Write-Host "  mcp-server-fetch: available (endpoint discovery will use MCP)" -ForegroundColor Green
} else {
    Write-Host "  mcp-server-fetch: not installed (endpoint discovery will use httpx fallback)" -ForegroundColor Yellow
    Write-Host "    To enable: pip install mcp-server-fetch" -ForegroundColor Gray
}

# 2. Check ARGUS MCP container; start if not running
if (Test-ArgusMcpRunning) {
    Write-Host "  ARGUS MCP (argus-mcp): running" -ForegroundColor Green
} else {
    Write-Host "  ARGUS MCP (argus-mcp): not running, starting..." -ForegroundColor Yellow

    if (-not (Test-Path $COMPOSE_FILE)) {
        Write-Host "[MCP] ERROR: docker-compose file not found: $COMPOSE_FILE" -ForegroundColor Red
        exit 1
    }

    Push-Location $ARGUS_ROOT
    try {
        $result = docker compose -f $COMPOSE_FILE up -d mcp-server 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            Write-Host "[MCP] ERROR: docker compose failed (exit $exitCode):" -ForegroundColor Red
            Write-Host $result -ForegroundColor Red
            exit 1
        }
    } finally {
        Pop-Location
    }

    Write-Host "  ARGUS MCP (argus-mcp): started, waiting for container..." -ForegroundColor Gray
    Start-Sleep -Seconds 3

    if (Test-ArgusMcpRunning) {
        Write-Host "  ARGUS MCP (argus-mcp): running" -ForegroundColor Green
    } else {
        Write-Host "  ARGUS MCP (argus-mcp): still not running after start" -ForegroundColor Yellow
        Write-Host "    Manual start: docker compose -f infra/docker-compose.yml up -d mcp-server" -ForegroundColor Gray
    }
}

Write-Host "[MCP] Ready. Report generation will use MCP when available." -ForegroundColor Gray
exit 0
