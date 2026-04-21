# ASCII-only: safe on Windows PowerShell 5.1 without UTF-8 BOM.
# Requires: cloudflared in PATH. Docs: docs/vercel-local-backend.md
<#
.SYNOPSIS
  Start Cloudflare Quick Tunnel to local ARGUS nginx.

.DESCRIPTION
  Runs: cloudflared tunnel --url http://127.0.0.1:<PORT>
  Port discovery (in priority order):
    1. -Port argument (overrides everything)
    2. ARGUS_HTTP_PORT from infra/.env (canonical, used by docker-compose)
    3. NGINX_HTTP_PORT from infra/.env (legacy alias)
    4. 8080 (matches infra/.env.example default)

  Quick tunnels are anonymous and the public URL ROTATES on every restart.
  For a stable URL, switch to a named tunnel via Cloudflare Zero Trust
  (Networks -> Tunnels -> Create) and use docker compose --profile tunnel up.

.PARAMETER Port
  Host port nginx listens on (e.g. 80 or 8080). -1 = auto-detect from .env.

.PARAMETER Protocol
  Tunnel transport: 'auto' (default), 'quic', or 'http2'.
  Use 'http2' on Windows when QUIC fails with "wsasendto ... buffer space"
  errors (a known UDP buffer issue on Windows; HTTP/2 uses TCP and is stable).

.EXAMPLE
  cd D:\path\ARGUS
  .\scripts\start-cloudflare-tunnel.ps1

.EXAMPLE
  .\scripts\start-cloudflare-tunnel.ps1 -Port 8080 -Protocol http2
#>
[CmdletBinding()]
param(
    [int]$Port = -1,
    [ValidateSet("auto", "quic", "http2")]
    [string]$Protocol = "auto"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot "infra\.env"

function Get-PortFromEnv {
    param(
        [string]$Path,
        [string[]]$Keys
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    foreach ($key in $Keys) {
        # Compose escapable key into a regex match (anchored, allows surrounding spaces)
        $pattern = '^\s*' + [regex]::Escape($key) + '\s*=\s*(\d+)\s*$'
        foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
            $t = $line.Trim()
            if ($t.Length -eq 0 -or $t.StartsWith("#")) {
                continue
            }
            if ($t -match $pattern) {
                return [pscustomobject]@{ Port = [int]$Matches[1]; Source = $key }
            }
        }
    }
    return $null
}

# 8080 matches infra/.env.example default for ARGUS_HTTP_PORT and is the
# value compose publishes (`${ARGUS_HTTP_PORT:-8080}:80`).
$listenPort = 8080
$portSource = "default"
if ($Port -ge 0) {
    $listenPort = $Port
    $portSource = "-Port arg"
}
else {
    # ARGUS_HTTP_PORT is canonical (used by infra/docker-compose.yml);
    # NGINX_HTTP_PORT is kept as a legacy alias for older .env files.
    $detected = Get-PortFromEnv -Path $EnvFile -Keys @("ARGUS_HTTP_PORT", "NGINX_HTTP_PORT")
    if ($null -ne $detected) {
        $listenPort = $detected.Port
        $portSource = "$($detected.Source) in infra/.env"
    }
}

$cf = Get-Command -Name "cloudflared" -ErrorAction SilentlyContinue
if (-not $cf) {
    Write-Error "cloudflared not in PATH. Install: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    exit 1
}

$origin = "http://127.0.0.1:$listenPort"
Write-Host "ARGUS Quick Tunnel -> $origin (port from: $portSource, protocol: $Protocol)" -ForegroundColor Cyan
Write-Host "Copy https://....trycloudflare.com from log; set Vercel NEXT_PUBLIC_BACKEND_URL; Redeploy. Leave window open." -ForegroundColor Yellow
Write-Host "NOTE: Quick tunnel URL ROTATES on each restart. For a stable URL use a named tunnel (docs/vercel-local-backend.md)." -ForegroundColor DarkYellow
Write-Host ""

# Fail fast: cloudflared will retry forever on a refused origin and Vercel
# will see Cloudflare 530 (Origin Unreachable) instead of a useful error.
try {
    $probe = Test-NetConnection -ComputerName 127.0.0.1 -Port $listenPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($probe -and -not $probe.TcpTestSucceeded) {
        Write-Error "Port $listenPort is not accepting TCP on 127.0.0.1. Start the stack first: cd infra; docker compose up -d nginx. Or pass -Port <hostPort> matching docker-compose.yml ports mapping."
        exit 2
    }
}
catch {
}

# Build cloudflared argv: --protocol forces transport when user asks for it.
$cfArgs = @("tunnel", "--url", $origin)
if ($Protocol -ne "auto") {
    $cfArgs += @("--protocol", $Protocol)
}
& cloudflared @cfArgs
