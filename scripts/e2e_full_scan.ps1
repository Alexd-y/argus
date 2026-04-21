<#
.SYNOPSIS
    ARG-047 — End-to-end capstone wrapper (Windows / PowerShell port).

.DESCRIPTION
    Mirrors ``scripts/e2e_full_scan.sh`` 1:1 so Windows operators get an
    identical experience to the Linux/macOS reference run. Drives the
    full ARGUS stack against a live OWASP Juice Shop and asserts the
    11-phase contract from Backlog/dev1_md §19.4. See
    ``docs/e2e-testing.md`` for the per-phase deep dive.

.PARAMETER Target
    Scan target URL. Default: ``http://juice-shop:3000`` (in-network DNS).
    From a Windows host shell, prefer ``http://localhost:3000``.

.PARAMETER BackendUrl
    Backend base URL. Default ``http://localhost:8000``.

.PARAMETER PrometheusUrl
    Prometheus base URL. Default ``http://localhost:9090``.

.PARAMETER Token
    API key sent as ``Authorization: Bearer …`` (default
    ``e2e-api-key-not-for-production`` — DO NOT use a production key).

.PARAMETER ScanMode
    ``quick`` | ``standard`` | ``deep`` (default ``standard``).

.PARAMETER MinFindings
    Threshold for Phase 10 assertion (default 50).

.PARAMETER ExpectedReports
    Default 12 (3 tiers × 4 formats). Raise to 18 once SARIF/JUNIT
    are exposed via the ``generate-all`` API.

.PARAMETER ResultsDir
    Override results directory (default ``e2e-results-<utc-stamp>``).

.PARAMETER ComposeFile
    Override compose file path (default ``infra/docker-compose.e2e.yml``).

.PARAMETER KeepStack
    Skip Phase 11 teardown for post-mortem inspection.

.NOTES
    Requires Windows PowerShell 5.1+ or PowerShell 7+, ``docker``, and
    ``python``. Tested on Windows 11 + Docker Desktop and PowerShell 7
    on Linux. Per-phase timeouts are enforced INSIDE each phase body
    (polling loops carry their own deadlines), not via Start-Job, to
    keep the wrapper's outer scope visible to all phase code.

    Exit codes: 0 success / 2 phase failure / 1 pre-flight failure.
#>

[CmdletBinding()]
param(
    [string]$Target,
    [string]$BackendUrl,
    [string]$PrometheusUrl,
    [string]$Token,
    [string]$ScanMode,
    [int]   $MinFindings     = 0,
    [int]   $ExpectedReports = 0,
    [string]$ResultsDir,
    [string]$ComposeFile,
    [switch]$KeepStack
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Defaults: parameter -> env var -> hard-coded default ─────────────────
function Resolve-Default {
    param([string]$ParamValue, [string]$EnvName, [string]$Fallback)
    if (-not [string]::IsNullOrEmpty($ParamValue)) { return $ParamValue }
    $env = (Get-Item -Path "env:$EnvName" -ErrorAction SilentlyContinue).Value
    if (-not [string]::IsNullOrEmpty($env)) { return $env }
    return $Fallback
}

$Target          = Resolve-Default $Target          'E2E_TARGET'           'http://juice-shop:3000'
$BackendUrl      = Resolve-Default $BackendUrl      'E2E_BACKEND_URL'      'http://localhost:8000'
$PrometheusUrl   = Resolve-Default $PrometheusUrl   'E2E_PROM_URL'         'http://localhost:9090'
$Token           = Resolve-Default $Token           'E2E_TOKEN'            'e2e-api-key-not-for-production'
$ScanMode        = Resolve-Default $ScanMode        'E2E_SCAN_MODE'        'standard'
if ($MinFindings     -le 0) { $MinFindings     = [int](Resolve-Default '' 'E2E_MIN_FINDINGS'     '50') }
if ($ExpectedReports -le 0) { $ExpectedReports = [int](Resolve-Default '' 'E2E_EXPECTED_REPORTS' '12') }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir '..')).Path
$ComposeFile = Resolve-Default $ComposeFile 'E2E_COMPOSE_FILE' (Join-Path $RepoRoot 'infra/docker-compose.e2e.yml')
$PythonBin   = Resolve-Default ''           'PYTHON_BIN'       'python'
$UtcStamp    = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$ResultsDir  = Resolve-Default $ResultsDir 'E2E_RESULTS_DIR'  (Join-Path $RepoRoot ("e2e-results-{0}" -f $UtcStamp))

# Per-phase wall-clock timeouts (seconds) — match bash wrapper.
$TimeoutComposeUp     = 300
$TimeoutBackendReady  = 180
$TimeoutScanComplete  = 2400
$TimeoutReportGen     = 600
$TimeoutVerify        = 120

# Mutable run state.
$script:ScanId        = ''
$script:BundleId      = ''
$script:FindingsCount = 0
$script:StartEpoch    = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

# ── Helpers ───────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Level, [string]$Message)
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Host ('{0} [{1}] {2}' -f $ts, $Level, $Message)
}

function Write-Info  { param([string]$m) Write-Log 'INFO ' $m }
function Write-Warn  { param([string]$m) Write-Log 'WARN ' $m }
function Write-Err   { param([string]$m) Write-Log 'ERROR' $m }

function Test-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required tool: $Name"
    }
}

function Write-PhaseJson {
    param([string]$Name, [string]$Status, [int]$Duration, [string]$Detail)
    $payload = [ordered]@{
        phase            = $Name
        status           = $Status
        duration_seconds = $Duration
        detail           = $Detail
        timestamp_utc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $out = Join-Path $ResultsDir ("phase-{0}.json" -f $Name)
    $payload | ConvertTo-Json -Depth 4 | Set-Content -Path $out -Encoding UTF8
}

function Write-Summary {
    param([string]$FailedPhase = '', [string]$Detail = '')
    $endEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $failedPhaseValue = $null
    if (-not [string]::IsNullOrEmpty($FailedPhase)) { $failedPhaseValue = $FailedPhase }
    $detailValue = $null
    if (-not [string]::IsNullOrEmpty($Detail)) { $detailValue = $Detail }
    $statusValue = 'passed'
    if (-not [string]::IsNullOrEmpty($FailedPhase)) { $statusValue = 'failed' }

    $payload = [ordered]@{
        schema                 = 'argus.e2e.summary/v1'
        stack                  = 'argus-e2e'
        task                   = 'ARG-047'
        target                 = $Target
        scan_mode              = $ScanMode
        scan_id                = $script:ScanId
        bundle_id              = $script:BundleId
        findings_count         = $script:FindingsCount
        min_findings_threshold = $MinFindings
        expected_reports       = $ExpectedReports
        duration_seconds       = ($endEpoch - $script:StartEpoch)
        failed_phase           = $failedPhaseValue
        failure_detail         = $detailValue
        status                 = $statusValue
        completed_at_utc       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $out = Join-Path $ResultsDir 'summary.json'
    $payload | ConvertTo-Json -Depth 4 | Set-Content -Path $out -Encoding UTF8
}

function Capture-Diagnostics {
    $diag = Join-Path $ResultsDir 'diagnostics'
    New-Item -ItemType Directory -Path $diag -Force | Out-Null
    foreach ($svc in @('juice-shop','argus-backend','argus-celery','argus-mcp','postgres','redis','minio','prometheus')) {
        try {
            & docker compose -f $ComposeFile logs --no-color --tail 500 $svc *>&1 |
                Set-Content -Path (Join-Path $diag "$svc.log") -Encoding UTF8
        } catch { }
    }
    try {
        & docker compose -f $ComposeFile ps --format json |
            Set-Content -Path (Join-Path $diag 'ps.json') -Encoding UTF8
    } catch { }
}

function Invoke-TeardownOnFailure {
    if ($KeepStack -or $env:E2E_KEEP_STACK -eq '1') {
        Write-Warn 'KeepStack=true — leaving stack running for inspection'
        return
    }
    Write-Warn 'Capturing diagnostics before teardown...'
    try { Capture-Diagnostics } catch { }
    Write-Warn 'Tearing down compose stack...'
    & docker compose -f $ComposeFile down -v --remove-orphans *>&1 | Out-Null
}

# Phase runner — invokes the body in-process (closures see outer scope) and
# converts any thrown exception into a structured failure record. Per-phase
# wall-clock timeouts are enforced inside each phase body (polling loops use
# their own deadlines).
function Invoke-Phase {
    param(
        [string]$Name,
        [string]$Description,
        [int]$Budget,
        [scriptblock]$Body
    )
    Write-Info ("Phase {0}: {1} (budget {2}s)" -f $Name, $Description, $Budget)
    $start = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    try {
        $detail = (& $Body 2>&1 | Out-String).TrimEnd()
    } catch {
        $end = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $dur = [int]($end - $start)
        Write-PhaseJson -Name $Name -Status 'failed' -Duration $dur -Detail $_.Exception.Message
        Write-Err ("Phase {0} FAILED after {1}s" -f $Name, $dur)
        Write-Err $_.Exception.Message
        Write-Summary -FailedPhase $Name -Detail $_.Exception.Message
        Invoke-TeardownOnFailure
        exit 2
    }
    $end = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $dur = [int]($end - $start)
    Write-PhaseJson -Name $Name -Status 'passed' -Duration $dur -Detail $detail
    Write-Info ("Phase {0} OK ({1}s)" -f $Name, $dur)
}

# ── Phase bodies ──────────────────────────────────────────────────────────

$phase01 = {
    Push-Location $RepoRoot
    try {
        & docker compose -f $ComposeFile pull --quiet *>&1 | Out-Null
        & docker compose -f $ComposeFile up -d --wait --wait-timeout 240
        if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (rc=$LASTEXITCODE)" }
        & docker compose -f $ComposeFile ps
    } finally { Pop-Location }
}

$phase02 = {
    $deadline = (Get-Date).AddSeconds($TimeoutBackendReady)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri "$BackendUrl/ready" -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
            if ($resp.StatusCode -eq 200) { Write-Output 'Backend /ready returned 200'; return }
        } catch { }
        Start-Sleep -Seconds 3
    }
    throw "Backend /ready did not return 200 within ${TimeoutBackendReady}s"
}

$phase03 = {
    $body = @{ target = $Target; email = 'e2e@example.com'; scan_mode = $ScanMode } | ConvertTo-Json -Compress
    $headers = @{ 'Content-Type' = 'application/json'; 'Authorization' = "Bearer $Token" }
    $resp = Invoke-RestMethod -Method Post -Uri "$BackendUrl/api/v1/scans" -Body $body -Headers $headers -TimeoutSec 30
    if (-not $resp.scan_id) {
        throw "Failed to extract scan_id from response: $($resp | ConvertTo-Json -Compress)"
    }
    $script:ScanId = $resp.scan_id
    Set-Content -Path (Join-Path $ResultsDir 'scan_id.txt') -Value $script:ScanId -Encoding UTF8
    Write-Output "scan_id=$($script:ScanId)"
}

$phase04 = {
    $deadline = (Get-Date).AddSeconds($TimeoutScanComplete)
    $headers = @{ 'Authorization' = "Bearer $Token" }
    $prevStatus = ''
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-RestMethod -Method Get -Uri "$BackendUrl/api/v1/scans/$($script:ScanId)" -Headers $headers -TimeoutSec 15
            if ($resp.status -ne $prevStatus) {
                Write-Info ("scan {0}: status={1} progress={2}% phase={3}" -f $script:ScanId, $resp.status, $resp.progress, $resp.phase)
                $prevStatus = $resp.status
            }
            if ($resp.status -eq 'completed') {
                Write-Output "Scan completed (final phase=$($resp.phase))"
                return
            }
            if ($resp.status -in @('failed', 'cancelled')) {
                throw "Scan terminated with status=$($resp.status) phase=$($resp.phase)"
            }
        } catch [System.Net.WebException] { Start-Sleep -Seconds 5; continue }
        Start-Sleep -Seconds 10
    }
    throw "Scan did not reach 'completed' within ${TimeoutScanComplete}s"
}

$phase05 = {
    $headers = @{ 'Content-Type' = 'application/json'; 'Authorization' = "Bearer $Token" }
    $resp = Invoke-RestMethod -Method Post -Uri "$BackendUrl/api/v1/scans/$($script:ScanId)/reports/generate-all" -Body '{}' -Headers $headers -TimeoutSec 30
    if ($resp.PSObject.Properties.Name -contains 'bundle_id' -and $resp.bundle_id) {
        $script:BundleId = $resp.bundle_id
        Set-Content -Path (Join-Path $ResultsDir 'bundle_id.txt') -Value $script:BundleId -Encoding UTF8
    }
    Write-Output ($resp | ConvertTo-Json -Compress)

    $deadline = (Get-Date).AddSeconds($TimeoutReportGen)
    $hdr = @{ 'Authorization' = "Bearer $Token" }
    $encodedTarget = [uri]::EscapeDataString($Target)
    while ((Get-Date) -lt $deadline) {
        try {
            $rows = Invoke-RestMethod -Method Get -Uri "$BackendUrl/api/v1/reports?target=$encodedTarget" -Headers $hdr -TimeoutSec 15
            $pending = ($rows | Where-Object { $_.generation_status -in @('pending', 'processing') }).Count
            if ($pending -eq 0) { Write-Output 'All reports moved out of pending/processing'; return }
        } catch { }
        Start-Sleep -Seconds 5
    }
    throw "Reports did not finish generating within ${TimeoutReportGen}s"
}

$phase06 = {
    & $PythonBin (Join-Path $ScriptDir 'e2e/verify_reports.py') `
        --backend-url $BackendUrl `
        --token $Token `
        --scan-id $script:ScanId `
        --target $Target `
        --expected-count $ExpectedReports `
        --output (Join-Path $ResultsDir 'verify_reports.json')
    if ($LASTEXITCODE -ne 0) { throw "verify_reports.py failed (rc=$LASTEXITCODE)" }
}

$phase07 = {
    & $PythonBin (Join-Path $ScriptDir 'e2e/verify_oast.py') `
        --backend-url $BackendUrl `
        --token $Token `
        --scan-id $script:ScanId `
        --output (Join-Path $ResultsDir 'verify_oast.json')
    if ($LASTEXITCODE -ne 0) { throw "verify_oast.py failed (rc=$LASTEXITCODE)" }
}

$phase08 = {
    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if (-not $bash) {
        Write-Warn 'bash not found on PATH — emitting cosign skip stub (dev convenience)'
        @{ status = 'skipped'; reason = 'bash unavailable on Windows host' } |
            ConvertTo-Json | Set-Content -Path (Join-Path $ResultsDir 'verify_cosign.json') -Encoding UTF8
        return
    }
    & bash (Join-Path $ScriptDir 'e2e/verify_cosign.sh') `
        --output (Join-Path $ResultsDir 'verify_cosign.json')
    if ($LASTEXITCODE -ne 0) { throw "verify_cosign.sh failed (rc=$LASTEXITCODE)" }
}

$phase09 = {
    & $PythonBin (Join-Path $ScriptDir 'e2e/verify_prometheus.py') `
        --prometheus-url $PrometheusUrl `
        --output (Join-Path $ResultsDir 'verify_prometheus.json')
    if ($LASTEXITCODE -ne 0) { throw "verify_prometheus.py failed (rc=$LASTEXITCODE)" }
}

$phase10 = {
    $headers = @{ 'Authorization' = "Bearer $Token" }
    $resp = Invoke-RestMethod -Method Get -Uri "$BackendUrl/api/v1/scans/$($script:ScanId)/findings/statistics" -Headers $headers -TimeoutSec 15
    $script:FindingsCount = [int]$resp.total
    @{ findings_count = $script:FindingsCount; threshold = $MinFindings } |
        ConvertTo-Json | Set-Content -Path (Join-Path $ResultsDir 'findings_count.json') -Encoding UTF8
    if ($script:FindingsCount -lt $MinFindings) {
        throw ("Insufficient findings: got {0}, need >= {1}" -f $script:FindingsCount, $MinFindings)
    }
    Write-Output ("Findings count OK: {0} (threshold {1})" -f $script:FindingsCount, $MinFindings)
}

$phase11 = {
    Capture-Diagnostics
    if ($KeepStack -or $env:E2E_KEEP_STACK -eq '1') {
        Write-Output 'KeepStack=true — skipping teardown'
        return
    }
    & docker compose -f $ComposeFile down -v --remove-orphans
    if ($LASTEXITCODE -ne 0) { throw "docker compose down failed (rc=$LASTEXITCODE)" }
}

$phase12 = {
    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if ($bash) {
        & bash (Join-Path $ScriptDir 'e2e/archive_results.sh') $ResultsDir
        if ($LASTEXITCODE -ne 0) { throw "archive_results.sh failed (rc=$LASTEXITCODE)" }
    } else {
        $zipPath = "$ResultsDir.zip"
        Compress-Archive -Path $ResultsDir -DestinationPath $zipPath -Force
        Write-Output "Archived to $zipPath"
    }
}

# ── Main ──────────────────────────────────────────────────────────────────

Write-Info ("ARG-047 e2e capstone — UTC {0}" -f $UtcStamp)
Write-Info ("Repo root:      {0}" -f $RepoRoot)
Write-Info ("Compose file:   {0}" -f $ComposeFile)
Write-Info ("Target:         {0}" -f $Target)
Write-Info ("Backend URL:    {0}" -f $BackendUrl)
Write-Info ("Scan mode:      {0}" -f $ScanMode)
Write-Info ("Min findings:   {0}" -f $MinFindings)
Write-Info ("Expected reps:  {0}" -f $ExpectedReports)
Write-Info ("Results dir:    {0}" -f $ResultsDir)

Test-Command 'docker'
Test-Command $PythonBin
& docker compose version *>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'docker compose v2 is required' }

New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
Write-Info ("Wrote run metadata to {0}" -f $ResultsDir)

Invoke-Phase '01_compose_up'        'Bring up Docker Compose stack'      $TimeoutComposeUp     $phase01
Invoke-Phase '02_backend_ready'     'Wait for backend /ready'             $TimeoutBackendReady  $phase02
Invoke-Phase '03_trigger_scan'      'POST /api/v1/scans'                  $TimeoutVerify        $phase03
Invoke-Phase '04_poll_scan'         'Poll scan until completed'           $TimeoutScanComplete  $phase04
Invoke-Phase '05_generate_reports'  'Generate report bundle'              $TimeoutReportGen     $phase05
Invoke-Phase '06_verify_reports'    'Verify report matrix'                $TimeoutVerify        $phase06
Invoke-Phase '07_verify_oast'       'Verify OAST evidence (best effort)'  $TimeoutVerify        $phase07
Invoke-Phase '08_verify_cosign'     'Verify cosign signatures'            $TimeoutVerify        $phase08
Invoke-Phase '09_verify_prometheus' 'Verify Prometheus metrics'           $TimeoutVerify        $phase09
Invoke-Phase '10_min_findings'      'Assert findings >= threshold'        $TimeoutVerify        $phase10
Invoke-Phase '11_teardown'          'Tear down stack & archive'           $TimeoutVerify        $phase11
Invoke-Phase '12_archive'           'Archive results'                     $TimeoutVerify        $phase12

Write-Summary
Write-Info ("All phases passed. Summary at {0}" -f (Join-Path $ResultsDir 'summary.json'))
exit 0
