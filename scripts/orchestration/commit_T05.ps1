#requires -Version 5.1
<#
.SYNOPSIS
    Commit T05 (heartbeat parsers → mapped, data-driven top-20).

.DESCRIPTION
    Hardened commit script (mirrors commit_T04 pattern):
    - Disables git pager; resets staging unless -KeepStaged.
    - Two atomic commits: (1) repo/docs/tests/fixtures, (2) workspace state + this script.
    - Assert-staged-exactly after each staging phase.

.PARAMETER DryRun
    Print what would be staged + committed; do NOT run git add/commit.

.PARAMETER KeepStaged
    Skip the initial `git reset` (only use if you have intentionally pre-staged files).

.EXAMPLE
    .\scripts\orchestration\commit_T05.ps1 -DryRun

.EXAMPLE
    .\scripts\orchestration\commit_T05.ps1

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

$repoRoot = (Invoke-Git -Args @('rev-parse', '--show-toplevel')).Trim()
Write-Host "==> Repo: $repoRoot"

if (-not (Test-Path "$repoRoot\backend\src\sandbox\parsers\discovery_text_parser.py")) {
    throw "Sanity check failed: discovery_text_parser.py not found. Did the worker run?"
}
Set-Location $repoRoot

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

$t05RepoFiles = @(
    'backend/src/sandbox/parsers/discovery_text_parser.py',
    'backend/src/sandbox/parsers/sqli_probe_text_parser.py',
    'backend/src/sandbox/parsers/jsql_probe_parser.py',
    'backend/src/sandbox/parsers/xss_auxiliary_json_parser.py',
    'backend/src/sandbox/parsers/__init__.py',
    'backend/tests/test_tool_catalog_coverage.py',
    'backend/tests/integration/sandbox/parsers/test_t05_heartbeat_top20_dispatch.py',
    'backend/tests/fixtures/heartbeat/t05/gobuster_dir.txt',
    'backend/tests/fixtures/heartbeat/t05/gobuster_auth.txt',
    'backend/tests/fixtures/heartbeat/t05/paramspider.txt',
    'backend/tests/fixtures/heartbeat/t05/hakrawler.txt',
    'backend/tests/fixtures/heartbeat/t05/waybackurls.txt',
    'backend/tests/fixtures/heartbeat/t05/linkfinder.txt',
    'backend/tests/fixtures/heartbeat/t05/subjs.txt',
    'backend/tests/fixtures/heartbeat/t05/secretfinder.txt',
    'backend/tests/fixtures/heartbeat/t05/kxss.txt',
    'backend/tests/fixtures/heartbeat/t05/joomscan.txt',
    'backend/tests/fixtures/heartbeat/t05/cmsmap.txt',
    'backend/tests/fixtures/heartbeat/t05/magescan.json',
    'backend/tests/fixtures/heartbeat/t05/xsstrike.json',
    'backend/tests/fixtures/heartbeat/t05/xsser.json',
    'backend/tests/fixtures/heartbeat/t05/playwright.json',
    'backend/tests/fixtures/heartbeat/t05/jsql.json',
    'backend/tests/fixtures/heartbeat/t05/ghauri.log',
    'backend/tests/fixtures/heartbeat/t05/tplmap.txt',
    'backend/tests/fixtures/heartbeat/t05/nosqlmap.txt',
    'backend/tests/fixtures/heartbeat/t05/arachni.afr',
    'backend/scripts/docs_tool_catalog.py',
    'docs/tool-catalog.md',
    'ai_docs/develop/parsers-t05-heartbeat-batch.md',
    'ai_docs/develop/issues/ISS-cycle6-carry-over.md'
)

Write-Host ""
Write-Host "==> Pre-flight: checking $($t05RepoFiles.Count) repo files exist + have changes"

$missing = @()
$unchanged = @()
foreach ($rel in $t05RepoFiles) {
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
    $t05RepoFiles = @($t05RepoFiles | Where-Object { $_ -notin $unchanged })
}

$skipCommit1 = ($t05RepoFiles.Count -eq 0)
if ($skipCommit1) {
    Write-Host ""
    Write-Host "[WARN] No T05 repo file changes — skipping commit 1 (workspace-only or nothing to do)." -ForegroundColor Yellow
}

if (-not $skipCommit1) {
    Write-Host ""
    Write-Host "==> Stage T05 repo files ($($t05RepoFiles.Count) files)"
    foreach ($f in $t05RepoFiles) {
        Stage-File -Path $f
    }

    if (-not $DryRun) {
        Assert-StagedExactly -Expected $t05RepoFiles -ContextLabel 'T05 (commit 1)'
    }
}

$commit1Body = @"
feat(parsers): data-driven heartbeat mapping for top-20 tools (T05)

- Add discovery, XSS JSON aux, jsql, and SQLi-probe text parsers; wire registry
- Ratchet 118 mapped / 39 heartbeat; _T05_NEWLY_MAPPED guard test
- Golden fixtures + parametrized dispatch tests (no ARG-020 heartbeat)
- Refresh docs/tool-catalog.md + docs_tool_catalog.py; ISS + ai_docs note

Refs T05.
"@

if ($DryRun) {
    if (-not $skipCommit1) {
        Write-Host ""
        Write-Host "==> [dry-run] Would commit with message:" -ForegroundColor DarkGray
        Write-Host $commit1Body -ForegroundColor DarkGray
    }
} elseif (-not $skipCommit1) {
    Write-Host ""
    Write-Host "==> Commit 1 (T05 repo files)"
    $commit1Body | Out-File -FilePath "$env:TEMP\argus_t05_msg.txt" -Encoding utf8 -NoNewline
    Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t05_msg.txt") | Out-Null
    Remove-Item "$env:TEMP\argus_t05_msg.txt" -Force -ErrorAction SilentlyContinue
    Write-Host "  + Commit 1 created: $((Invoke-Git -Args @('rev-parse', '--short', 'HEAD')).Trim())" -ForegroundColor Green
}

$workspaceFiles = @(
    '.cursor/workspace/active/orch-argus-20260420-1430/notes/T05-methodology.md',
    '.cursor/workspace/active/orch-argus-20260420-1430/tasks.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/progress.json',
    'scripts/orchestration/commit_T05.ps1'
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

$commit2Body = @"
chore(workspace): T05 orchestration state (orch-argus-20260420-1430)

- notes/T05-methodology.md, tasks.json, progress.json: T05 tracking
- scripts/orchestration/commit_T05.ps1: two-commit allow-list script

Refs T05, orchestration:orch-argus-20260420-1430.
"@

if ($DryRun) {
    Write-Host ""
    Write-Host "==> [dry-run] Would commit with message:" -ForegroundColor DarkGray
    Write-Host $commit2Body -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Done (dry-run)." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "==> Commit 2 (workspace state)"
$commit2Body | Out-File -FilePath "$env:TEMP\argus_t05_ws_msg.txt" -Encoding utf8 -NoNewline
Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t05_ws_msg.txt") | Out-Null
Remove-Item "$env:TEMP\argus_t05_ws_msg.txt" -Force -ErrorAction SilentlyContinue
Write-Host "  + Commit 2 created: $((Invoke-Git -Args @('rev-parse', '--short', 'HEAD')).Trim())" -ForegroundColor Green

Write-Host ""
Write-Host "==> Recent log:"
Invoke-Git -Args @('log', '--oneline', '-n', '5')

Write-Host ""
Write-Host "Done." -ForegroundColor Green
