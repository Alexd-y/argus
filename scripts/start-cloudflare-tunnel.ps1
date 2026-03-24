# ASCII-only: safe on Windows PowerShell 5.1 without UTF-8 BOM.
# Requires: cloudflared in PATH. Docs: docs/vercel-local-backend.md
<#
.SYNOPSIS
  Start Cloudflare Quick Tunnel to local ARGUS nginx.

.DESCRIPTION
  Runs: cloudflared tunnel --url http://127.0.0.1:<PORT>
  Port: NGINX_HTTP_PORT from infra/.env if present, else 80, unless -Port is set.

.PARAMETER Port
  Host port nginx listens on (e.g. 80 or 8080). -1 = read infra/.env.

.EXAMPLE
  cd D:\path\ARGUS
  .\scripts\start-cloudflare-tunnel.ps1

.EXAMPLE
  .\scripts\start-cloudflare-tunnel.ps1 -Port 8080
#>
[CmdletBinding()]
param(
    [int]$Port = -1
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot "infra\.env"

function Get-NginxPortFromEnv {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith("#")) {
            continue
        }
        if ($t -match '^\s*NGINX_HTTP_PORT\s*=\s*(\d+)\s*$') {
            return [int]$Matches[1]
        }
    }
    return $null
}

$listenPort = 80
if ($Port -ge 0) {
    $listenPort = $Port
}
else {
    $fromEnv = Get-NginxPortFromEnv -Path $EnvFile
    if ($null -ne $fromEnv) {
        $listenPort = $fromEnv
    }
}

$cf = Get-Command -Name "cloudflared" -ErrorAction SilentlyContinue
if (-not $cf) {
    Write-Error "cloudflared not in PATH. Install: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    exit 1
}

$origin = "http://127.0.0.1:$listenPort"
Write-Host "ARGUS Quick Tunnel -> $origin (local nginx)" -ForegroundColor Cyan
Write-Host "Copy https://....trycloudflare.com from log; set Vercel NEXT_PUBLIC_BACKEND_URL; Redeploy. Leave window open." -ForegroundColor Yellow
Write-Host ""

try {
    $probe = Test-NetConnection -ComputerName 127.0.0.1 -Port $listenPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($probe -and -not $probe.TcpTestSucceeded) {
        Write-Warning "Port $listenPort not accepting TCP. Start Docker/nginx or use -Port."
    }
}
catch {
}

& cloudflared tunnel --url $origin
