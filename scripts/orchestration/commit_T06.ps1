#requires -Version 5.1
<#
.SYNOPSIS
    Commit T06 (mypy Windows access-violation root-cause + WSL2 docs) to the ARGUS repo.

.DESCRIPTION
    Hardened commit script (mirrors commit_T02.ps1 / commit_T03.ps1 v2 safety pattern):
    - Disables git pager to avoid interactive hangs.
    - Resets the staging area at start to avoid contamination from prior runs.
    - Stages an explicit allow-list of files; assert-staged-exactly check after each step.
    - Two atomic commits:
        1. T06 docs (4 files: 2 new + README + ISS-cycle6).
        2. Workspace-state files (.cursor/workspace/active/orch-argus-.../...).

    PRE-CONDITION: T02 + T03 commits should land first because all three commits
    touch ai_docs/develop/issues/ISS-cycle6-carry-over.md (T03: ARG-058 closure;
    T06: Item 1 closure). Running in T02 -> T03 -> T06 order keeps the diff
    of each commit narrowly scoped to its task's intent.

.PARAMETER DryRun
    Print what would be staged + committed; do NOT actually run git add/commit.

.PARAMETER KeepStaged
    Skip the initial `git reset` (only use if you have intentionally pre-staged files).

.EXAMPLE
    # Preview what would happen (RECOMMENDED FIRST RUN):
    .\scripts\orchestration\commit_T06.ps1 -DryRun

.EXAMPLE
    # Real commit:
    .\scripts\orchestration\commit_T06.ps1

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
# Helpers (mirror commit_T02 / commit_T03)
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
        if ($extra)   { Write-Host "Extra (must be removed):"; $extra   | ForEach-Object { Write-Host "  + $_" -ForegroundColor Yellow } }
        if ($missing) { Write-Host "Missing (must be added):"; $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow } }
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

if (-not (Test-Path "$repoRoot\ai_docs\develop\troubleshooting\mypy-windows-access-violation.md")) {
    throw "Sanity check failed: mypy-windows-access-violation.md not found. Did the worker run?"
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
# 2. T06 allow-list
# --------------------------------------------------------------------------

$t06Files = @(
    'ai_docs/develop/troubleshooting/mypy-windows-access-violation.md',
    'ai_docs/develop/wsl2-setup.md',
    'README.md',
    'ai_docs/develop/issues/ISS-cycle6-carry-over.md'
)

# --------------------------------------------------------------------------
# 3. Pre-flight
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "==> Pre-flight: checking $($t06Files.Count) files exist + have changes"

$missing = @()
$unchanged = @()
foreach ($rel in $t06Files) {
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
    Write-Host "Possible cause: ISS-cycle6-carry-over.md was already committed under T03." -ForegroundColor Yellow
    Write-Host "If T06 added more changes to it that are still uncommitted, this should not show up here." -ForegroundColor Yellow
    $t06Files = @($t06Files | Where-Object { $_ -notin $unchanged })
}

# --------------------------------------------------------------------------
# 4. Stage commit 1
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "==> Stage T06 doc files ($($t06Files.Count) files)"
foreach ($f in $t06Files) {
    Stage-File -Path $f
}

if (-not $DryRun) {
    Assert-StagedExactly -Expected $t06Files -ContextLabel 'T06 (commit 1)'
}

# --------------------------------------------------------------------------
# 5. Commit 1
# --------------------------------------------------------------------------

$commit1Body = @"
docs(dev): document mypy Windows access-violation + WSL2 setup runbook (T06)

Add a troubleshooting doc and an onboarding runbook to support Windows
developers who hit the well-known mypy STATUS_ACCESS_VIOLATION (0xC0000005)
during type-check.

- ai_docs/develop/troubleshooting/mypy-windows-access-violation.md (NEW):
  symptom + verbatim crash log fingerprint, affected versions
  (mypy 1.10..1.20.x, Python 3.12.x, Windows 10/11), top-3 root-cause
  hypotheses (mypyc + incremental-cache corruption is most likely),
  pure-Windows secondary workarounds (clear cache, --no-incremental,
  narrow Defender exclusions on backend\.mypy_cache + backend\src,
  Win32 long-path support), why upstream fix is non-trivial (multiple
  open python/mypy issues match the fingerprint), verification, CI impact
  (none -- CI uses ubuntu-latest).
- ai_docs/develop/wsl2-setup.md (NEW): full Windows-host onboarding
  runbook -- prereqs, ``wsl --install``, deadsnakes Python 3.12 (PPA
  setup ordered correctly so apt install actually finds the package),
  apt build chain (libpq-dev + WeasyPrint deps), clone-into-ext4 not
  /mnt rationale (file IO + semantics), dev-stack bring-up, venv +
  deps, pytest/mypy/argus_validate, Cursor / VS Code WSL integration,
  performance notes, common pitfalls table.
- README.md: 1-paragraph "Windows users" note in Development section
  pointing at both new docs.
- ai_docs/develop/issues/ISS-cycle6-carry-over.md: carry-over Item 1
  (mypy Windows bug) marked **RESOLVED (Cycle 6, T06 -- 2026-04-21)**;
  original problem statement preserved for auditor traceability.

No mypy / pyproject / CI / production source changed. ``argus_validate.py``
Gate ``mypy_capstone`` remains required=False.

NOTE: Reviewer flagged a CRITICAL out-of-scope finding (real-looking
provider API keys committed in infra/.env.example). Tracked separately
as ARG-SEC-001 -- see .cursor/workspace/active/orch-argus-20260420-1430/notes/T06-followups.md.

Refs T06.
"@

if ($DryRun) {
    Write-Host ""
    Write-Host "==> [dry-run] Would commit with message:" -ForegroundColor DarkGray
    Write-Host $commit1Body -ForegroundColor DarkGray
} else {
    Write-Host ""
    Write-Host "==> Commit 1 (T06 docs)"
    $commit1Body | Out-File -FilePath "$env:TEMP\argus_t06_msg.txt" -Encoding utf8 -NoNewline
    Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t06_msg.txt") | Out-Null
    Remove-Item "$env:TEMP\argus_t06_msg.txt" -Force -ErrorAction SilentlyContinue
    Write-Host "  + Commit 1 created: $((Invoke-Git -Args @('rev-parse', '--short', 'HEAD')).Trim())" -ForegroundColor Green
}

# --------------------------------------------------------------------------
# 6. Stage commit 2 (workspace state)
# --------------------------------------------------------------------------

$workspaceFiles = @(
    '.cursor/workspace/active/orch-argus-20260420-1430/tasks.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/progress.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/notes/T06-followups.md',
    'scripts/orchestration/commit_T06.ps1'
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
chore(workspace): mark T06 completed in orchestration state (orch-argus-20260420-1430)

- tasks.json: T06 status -> completed; deliverables, MIN-001/002/004 polish, MIN-003 deferred to Cycle 7, SEC-001 escalation recorded
- progress.json: completedTasks 2 -> 3; currentTask T06 -> T07; T06 commit recorded as ready; SEC-001 listed under criticalEscalations
- notes/T06-followups.md (NEW): SEC-001 emergency action list (rotate 6 keys + git history purge + pre-commit gate) + MIN-003 Cycle 7 input
- scripts/orchestration/commit_T06.ps1 (NEW): hardened commit script

Refs T06, orchestration:orch-argus-20260420-1430.
"@

if ($DryRun) {
    Write-Host ""
    Write-Host "==> [dry-run] Would commit with message:" -ForegroundColor DarkGray
    Write-Host $commit2Body -ForegroundColor DarkGray
} else {
    Write-Host ""
    Write-Host "==> Commit 2 (workspace state)"
    $commit2Body | Out-File -FilePath "$env:TEMP\argus_t06_ws_msg.txt" -Encoding utf8 -NoNewline
    Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t06_ws_msg.txt") | Out-Null
    Remove-Item "$env:TEMP\argus_t06_ws_msg.txt" -Force -ErrorAction SilentlyContinue
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
Write-Host ""
Write-Host "[!] OUT-OF-SCOPE CRITICAL: infra/.env.example contains real-looking API keys." -ForegroundColor Red
Write-Host "    See .cursor/workspace/active/orch-argus-20260420-1430/notes/T06-followups.md" -ForegroundColor Red
Write-Host "    Rotate keys at provider dashboards NOW (assume already burned)." -ForegroundColor Red
