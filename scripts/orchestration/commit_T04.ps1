#requires -Version 5.1
<#
.SYNOPSIS
    Commit T04 (opt-in SARIF and JUnit export API) to the ARGUS repo.

.DESCRIPTION
    Hardened commit script (mirrors commit_T08 safety pattern):
    - Disables git pager to avoid interactive hangs.
    - Resets the staging area at start to avoid contamination from prior runs.
    - Stages an explicit allow-list; assert-staged-exactly check after each step.
    - Two atomic commits:
        1. T04 alembic, models, reports, API routes, tests, docs, ISS (10 files).
        2. Workspace-state files (.cursor/workspace/active/orch-argus-.../...) + this script.

    PRE-CONDITION: Prefer T01 commits first when ISS-cycle6-carry-over.md ordering matters;
    land T04 before T09 if that file is touched again by later tasks.

.PARAMETER DryRun
    Print what would be staged + committed; do NOT actually run git add/commit.

.PARAMETER KeepStaged
    Skip the initial `git reset` (only use if you have intentionally pre-staged files).

.EXAMPLE
    .\scripts\orchestration\commit_T04.ps1 -DryRun

.EXAMPLE
    .\scripts\orchestration\commit_T04.ps1

.NOTES
    Git pager: $env:GIT_PAGER='cat', $env:PAGER='cat'; Invoke-Git prepends --no-pager on every call.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$KeepStaged
)

$ErrorActionPreference = 'Stop'
$env:GIT_PAGER = 'cat'
$env:PAGER = 'cat'

# --------------------------------------------------------------------------
# Helpers (mirror commit_T08)
# --------------------------------------------------------------------------

function Invoke-Git {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Args)
    $allArgs = @('--no-pager') + $Args
    $output = & git @allArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "[FATAL] git $($Args -join ' ') exited $LASTEXITCODE" -ForegroundColor Red
        Write-Host $output
        throw "git command failed: $($Args -join ' ')"
    }
    return $output
}

function Assert-StagedExactly {
    param(
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$ContextLabel
    )
    $rawStaged = Invoke-Git -Args @('diff', '--cached', '--name-only')
    $actual = @(
        $rawStaged | Where-Object { $_ -and $_.Trim() } | ForEach-Object { ($_ -replace '\\', '/').Trim() }
    )
    $expectedNorm = @($Expected | ForEach-Object { ($_ -replace '\\', '/').Trim() })

    $sortedActual = ($actual | Sort-Object) -join "`n"
    $sortedExpected = ($expectedNorm | Sort-Object) -join "`n"

    if ($sortedActual -ne $sortedExpected) {
        $extra = @($actual | Where-Object { $_ -notin $expectedNorm })
        $missing = @($expectedNorm | Where-Object { $_ -notin $actual })
        Write-Host ""
        Write-Host "[FATAL] Staged set mismatch for $ContextLabel" -ForegroundColor Red
        Write-Host "Expected ($($expectedNorm.Count) files):"
        $expectedNorm | Sort-Object | ForEach-Object { Write-Host "  $_" }
        Write-Host "Actual ($($actual.Count) files):"
        $actual | Sort-Object | ForEach-Object { Write-Host "  $_" }
        if ($extra)   { Write-Host "Extra (must be removed):";   $extra   | ForEach-Object { Write-Host "  + $_" -ForegroundColor Yellow } }
        if ($missing) { Write-Host "Missing (must be added):";   $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow } }
        Write-Host ""
        Write-Host "Aborting. Reset with `git reset` and rerun with -DryRun." -ForegroundColor Red
        throw "staged-set assertion failed for $ContextLabel"
    }
    Write-Host "  + Staged set verified ($($actual.Count) files) for $ContextLabel" -ForegroundColor Green
}

function Stage-File {
    param([Parameter(Mandatory)][string]$Path)
    if ($DryRun) {
        Write-Host "  [dry-run] git add -- $Path" -ForegroundColor DarkGray
    } else {
        Invoke-Git -Args @('add', '--', $Path) | Out-Null
    }
}

# --------------------------------------------------------------------------
# 0. Sanity
# --------------------------------------------------------------------------

$repoRoot = (Invoke-Git -Args @('rev-parse', '--show-toplevel')).Trim()
Write-Host "==> Repo: $repoRoot"

if (-not (Test-Path "$repoRoot\backend\alembic\versions\024_tenant_exports_sarif_junit.py")) {
    throw "Sanity check failed: 024_tenant_exports_sarif_junit.py not found. Did the worker run?"
}
Set-Location $repoRoot

# --------------------------------------------------------------------------
# 1. Reset staging
# --------------------------------------------------------------------------

if (-not $KeepStaged) {
    Write-Host ""
    Write-Host "==> Resetting staging area"
    if ($DryRun) {
        Write-Host "  [dry-run] git reset" -ForegroundColor DarkGray
    } else {
        Invoke-Git -Args @('reset') | Out-Null
    }
} else {
    Write-Host "  (skipping git reset because -KeepStaged was passed)" -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# 2. T04 allow-list (tasks.json T04 deliverables)
# --------------------------------------------------------------------------

$t04Files = @(
    'backend/alembic/versions/024_tenant_exports_sarif_junit.py',
    'backend/src/db/models.py',
    'backend/src/reports/generators.py',
    'backend/src/api/routers/scans.py',
    'backend/src/api/routers/admin.py',
    'backend/tests/unit/reports/test_build_report_data_from_scan_findings.py',
    'backend/tests/unit/api/test_scan_findings_export.py',
    'backend/tests/integration/migrations/test_alembic_smoke.py',
    'ai_docs/develop/api/findings-sarif-junit-export.md',
    'ai_docs/develop/issues/ISS-cycle6-carry-over.md'
)

# --------------------------------------------------------------------------
# 3. Pre-flight
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "==> Pre-flight: checking $($t04Files.Count) files exist + have changes"

$missing = @()
$unchanged = @()
foreach ($rel in $t04Files) {
    $abs = Join-Path $repoRoot ($rel -replace '/', '\')
    if (-not (Test-Path $abs)) {
        $missing += $rel
        continue
    }
    $statusLine = (Invoke-Git -Args @('status', '--porcelain', '--', $rel)) -join "`n"
    if (-not $statusLine.Trim()) {
        $unchanged += $rel
    }
}

if ($missing) {
    Write-Host ""
    Write-Host "[FATAL] Missing files:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" }
    throw "missing files in allow-list"
}

if ($unchanged) {
    Write-Host ""
    Write-Host "[WARN] Files in allow-list with no git changes:" -ForegroundColor Yellow
    $unchanged | ForEach-Object { Write-Host "  $_" }
    $t04Files = @($t04Files | Where-Object { $_ -notin $unchanged })
}

$skipCommit1 = ($t04Files.Count -eq 0)
if ($skipCommit1) {
    Write-Host ""
    Write-Host "[WARN] No T04 repo file changes — skipping commit 1 (workspace-only or nothing to do)." -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# 4–5. Stage + commit 1 (repo allow-list)
# --------------------------------------------------------------------------

if (-not $skipCommit1) {
    Write-Host ""
    Write-Host "==> Stage T04 repo files ($($t04Files.Count) files)"
    foreach ($f in $t04Files) {
        Stage-File -Path $f
    }

    if (-not $DryRun) {
        Assert-StagedExactly -Expected $t04Files -ContextLabel 'T04 (commit 1)'
    }

    $commit1Body = @"
feat(api): opt-in SARIF and JUnit export (T04)

Per-tenant flag (Alembic 024 + Tenant.exports_sarif_junit_enabled), report data
from scan findings, export routes on scans router, admin TenantOut/PATCH.
Unit tests for report builders and export endpoints; alembic smoke chain includes 024.
API doc findings-sarif-junit-export.md; ISS-cycle6-carry-over item 2 RESOLVED.

Refs T04.
"@

    if ($DryRun) {
        Write-Host ""
        Write-Host "==> [dry-run] Would commit with message:" -ForegroundColor DarkGray
        Write-Host $commit1Body -ForegroundColor DarkGray
    } else {
        Write-Host ""
        Write-Host "==> Commit 1 (T04 repo files)"
        $commit1Body | Out-File -FilePath "$env:TEMP\argus_t04_msg.txt" -Encoding utf8 -NoNewline
        Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t04_msg.txt") | Out-Null
        Remove-Item "$env:TEMP\argus_t04_msg.txt" -Force -ErrorAction SilentlyContinue
        Write-Host "  + Commit 1 created: $((Invoke-Git -Args @('rev-parse', '--short', 'HEAD')).Trim())" -ForegroundColor Green
    }
}

# --------------------------------------------------------------------------
# 6. Stage commit 2 (workspace state)
# --------------------------------------------------------------------------

$workspaceFiles = @(
    '.cursor/workspace/active/orch-argus-20260420-1430/tasks.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/progress.json',
    'scripts/orchestration/commit_T04.ps1'
)

$workspaceStage = New-Object System.Collections.Generic.List[string]
foreach ($rel in $workspaceFiles) {
    $abs = Join-Path $repoRoot ($rel -replace '/', '\')
    if (-not (Test-Path $abs)) {
        Write-Host "  (skipping $rel - file does not exist)" -ForegroundColor DarkGray
        continue
    }
    $statusLine = (Invoke-Git -Args @('status', '--porcelain', '--', $rel)) -join "`n"
    if ($statusLine.Trim()) {
        $null = $workspaceStage.Add($rel)
    } else {
        Write-Host "  (skipping $rel - no changes)" -ForegroundColor DarkGray
    }
}

if ($workspaceStage.Count -eq 0) {
    Write-Host ""
    Write-Host "==> Nothing to commit for workspace state. Done." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "==> Stage workspace-state files ($($workspaceStage.Count) files)"
foreach ($f in $workspaceStage) {
    Stage-File -Path $f
}

if (-not $DryRun) {
    Assert-StagedExactly -Expected $workspaceStage -ContextLabel 'workspace (commit 2)'
}

# --------------------------------------------------------------------------
# 7. Commit 2
# --------------------------------------------------------------------------

$commit2Body = @"
chore(workspace): T04 orchestration state (orch-argus-20260420-1430)

- tasks.json / progress.json: T04 tracking as needed
- scripts/orchestration/commit_T04.ps1: hardened two-commit allow-list script

Refs T04, orchestration:orch-argus-20260420-1430.
"@

if ($DryRun) {
    Write-Host ""
    Write-Host "==> [dry-run] Would commit with message:" -ForegroundColor DarkGray
    Write-Host $commit2Body -ForegroundColor DarkGray
} else {
    Write-Host ""
    Write-Host "==> Commit 2 (workspace state)"
    $commit2Body | Out-File -FilePath "$env:TEMP\argus_t04_ws_msg.txt" -Encoding utf8 -NoNewline
    Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t04_ws_msg.txt") | Out-Null
    Remove-Item "$env:TEMP\argus_t04_ws_msg.txt" -Force -ErrorAction SilentlyContinue
    Write-Host "  + Commit 2 created: $((Invoke-Git -Args @('rev-parse', '--short', 'HEAD')).Trim())" -ForegroundColor Green
}

# --------------------------------------------------------------------------
# 8. Done
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "==> Recent log:"
Invoke-Git -Args @('log', '--oneline', '-n', '5')

Write-Host ""
Write-Host "Done." -ForegroundColor Green
