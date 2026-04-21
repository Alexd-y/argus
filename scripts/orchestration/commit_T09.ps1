#requires -Version 5.1
<#
.SYNOPSIS
    Commit T09 (Renovate sandbox watcher + advisory SBOM drift check) to the ARGUS repo.

.DESCRIPTION
    Two atomic commits (mirrors commit_T08 pattern):
      1. renovate.json, drift script, CI step, baselines dir, docs, ISS.
      2. Workspace orchestration state + this script.

.PARAMETER DryRun
    Print what would be staged + committed; do NOT run git add/commit.

.PARAMETER KeepStaged
    Skip the initial git reset.

.EXAMPLE
    .\scripts\orchestration\commit_T09.ps1 -DryRun

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
        if ($extra)   { Write-Host "Extra:";   $extra   | ForEach-Object { Write-Host "  + $_" -ForegroundColor Yellow } }
        if ($missing) { Write-Host "Missing:"; $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow } }
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

if (-not (Test-Path "$repoRoot\renovate.json")) {
    throw "Sanity check failed: renovate.json not found."
}
Set-Location $repoRoot

if (-not $KeepStaged) {
    Write-Host ""
    Write-Host "==> Resetting staging area"
    if (-not $DryRun) {
        Invoke-Git -Args @('reset') | Out-Null
    }
} else {
    Write-Host "  (skipping git reset — KeepStaged)" -ForegroundColor Yellow
}

$t09Files = @(
    'renovate.json',
    'infra/scripts/sbom_drift_check.py',
    'sandbox/images/sbom-baselines/.gitkeep',
    '.github/workflows/sandbox-images.yml',
    'ai_docs/develop/sandbox-sbom-renovate.md',
    'ai_docs/develop/ci-cd.md',
    'ai_docs/develop/issues/ISS-cycle6-carry-over.md'
)

Write-Host ""
Write-Host "==> Pre-flight: $($t09Files.Count) files"

$missing = @()
$unchanged = @()
foreach ($rel in $t09Files) {
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
    Write-Host "[FATAL] Missing:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" }
    throw "missing files"
}

if ($unchanged) {
    Write-Host "[WARN] No git changes for:" -ForegroundColor Yellow
    $unchanged | ForEach-Object { Write-Host "  $_" }
    $t09Files = @($t09Files | Where-Object { $_ -notin $unchanged })
}

Write-Host ""
Write-Host "==> Stage T09 ($($t09Files.Count) files)"
foreach ($f in $t09Files) {
    Stage-File -Path $f
}

if (-not $DryRun) {
    Assert-StagedExactly -Expected $t09Files -ContextLabel 'T09 (commit 1)'
}

$commit1Body = @"
chore(ci): sandbox SBOM Renovate watcher (T09)

Add root renovate.json (dockerfile manager scoped to six sandbox Dockerfiles):
weekly schedule, grouped kalilinux/kali-rolling bumps with digest pinning,
supply-chain labels, docker/dockerfile syntax image ignored.

Add infra/scripts/sbom_drift_check.py and an advisory continue-on-error step
in sandbox-images.yml comparing extracted CycloneDX fingerprints to optional
sandbox/images/sbom-baselines/<profile>.json.

Document operator flow in ai_docs/develop/sandbox-sbom-renovate.md and ci-cd.md;
mark ISS-cycle6-carry-over sandbox SBOM item RESOLVED.

Files:
  + renovate.json
  + infra/scripts/sbom_drift_check.py
  + sandbox/images/sbom-baselines/.gitkeep
  M .github/workflows/sandbox-images.yml
  + ai_docs/develop/sandbox-sbom-renovate.md
  M ai_docs/develop/ci-cd.md
  M ai_docs/develop/issues/ISS-cycle6-carry-over.md

Refs T09.
"@

if ($DryRun) {
    Write-Host ""
    Write-Host "[dry-run] Commit 1 message:" -ForegroundColor DarkGray
    Write-Host $commit1Body
} else {
    Write-Host ""
    Write-Host "==> Commit 1"
    $commit1Body | Out-File -FilePath "$env:TEMP\argus_t09_msg.txt" -Encoding utf8 -NoNewline
    Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t09_msg.txt") | Out-Null
    Remove-Item "$env:TEMP\argus_t09_msg.txt" -Force -ErrorAction SilentlyContinue
    Write-Host "  + $(Invoke-Git -Args @('rev-parse', '--short', 'HEAD'))" -ForegroundColor Green
}

$workspaceFiles = @(
    '.cursor/workspace/active/orch-argus-20260420-1430/tasks.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/progress.json',
    'scripts/orchestration/commit_T09.ps1'
)

$workspaceStage = New-Object System.Collections.Generic.List[string]
foreach ($rel in $workspaceFiles) {
    $abs = Join-Path $repoRoot ($rel -replace '/', '\')
    if (-not (Test-Path $abs)) {
        Write-Host "  (skip missing $rel)" -ForegroundColor DarkGray
        continue
    }
    $statusLine = (Invoke-Git -Args @('status', '--porcelain', '--', $rel)) -join "`n"
    if ($statusLine.Trim()) {
        $null = $workspaceStage.Add($rel)
    }
}

if ($workspaceStage.Count -eq 0) {
    Write-Host ""
    Write-Host "==> No workspace changes; done." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "==> Stage workspace ($($workspaceStage.Count) files)"
foreach ($f in $workspaceStage) {
    Stage-File -Path $f
}

if (-not $DryRun) {
    Assert-StagedExactly -Expected $workspaceStage -ContextLabel 'workspace (commit 2)'
}

$commit2Body = @"
chore(workspace): mark T09 completed (orch-argus-20260420-1430)

- tasks.json: T09 completed + deliverables
- progress.json: completedTasks 7; currentTask T10; pendingCommits + commit_T09.ps1
- scripts/orchestration/commit_T09.ps1

Refs T09.
"@

if ($DryRun) {
    Write-Host "[dry-run] Commit 2 message:" -ForegroundColor DarkGray
    Write-Host $commit2Body
} else {
    Write-Host ""
    Write-Host "==> Commit 2"
    $commit2Body | Out-File -FilePath "$env:TEMP\argus_t09_ws_msg.txt" -Encoding utf8 -NoNewline
    Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t09_ws_msg.txt") | Out-Null
    Remove-Item "$env:TEMP\argus_t09_ws_msg.txt" -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Invoke-Git -Args @('log', '--oneline', '-n', '5')
Write-Host "Done." -ForegroundColor Green
