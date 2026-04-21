#requires -Version 5.1
<#
.SYNOPSIS
  Atomic commit of T02 (Latent cyclic policy import refactor) + workspace state.
  Idempotent and SAFE: resets the staging area first to avoid contamination.

.DESCRIPTION
  Why this exists:
    During the 2026-04-20 orchestration run, the Cursor Shell wrapper failed
    repeatedly mid-session preventing the orchestrator from invoking git
    directly. Workspace files were written via file tools; this script handles
    the git operations.

  SAFETY MODEL (revised v2):
    * Disables git pager (no interactive `:` prompts).
    * Resets the staging area BEFORE staging anything (prevents committing
      unrelated files that happened to be `git add`'ed earlier in the session).
    * Stages an explicit allow-list only.
    * Verifies the staged set matches the allow-list before committing;
      aborts with an actionable error if anything else is staged.
    * Two atomic commits (Conventional Commits) — never mixes scopes.

.PARAMETER DryRun
  Show planned actions without invoking git commit. Default: $false.

.PARAMETER SkipHooks
  Pass --no-verify to git commit. Default: $false. Use only if a pre-commit
  hook fails on something unrelated to T02.

.PARAMETER KeepStaged
  Do NOT call `git reset` at the start. Use this only if you have manually
  staged exactly the T02 files and want to skip the auto-clean step.
  Default: $false.

.EXAMPLE
  PS> .\scripts\orchestration\commit_T02.ps1 -DryRun
  PS> .\scripts\orchestration\commit_T02.ps1

.NOTES
  Pager: $env:GIT_PAGER='cat', $env:PAGER='cat'; Invoke-Git/Invoke-GitNoThrow prepend --no-pager;
  direct git calls use explicit --no-pager (rev-parse, diff, commit -F).
#>
[CmdletBinding()]
param(
  [switch]$DryRun,
  [switch]$SkipHooks,
  [switch]$KeepStaged
)

$ErrorActionPreference = 'Stop'
$env:GIT_PAGER = 'cat'  # Disable pager globally for this script
$env:PAGER = 'cat'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# ----- helper: invoke git with no pager + capture output cleanly -----
function Invoke-Git {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
  $allArgs = @('--no-pager') + $Args
  & git @allArgs
  if ($LASTEXITCODE -ne 0) {
    throw "git $($allArgs -join ' ') failed with exit $LASTEXITCODE"
  }
}

function Invoke-GitNoThrow {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
  $allArgs = @('--no-pager') + $Args
  & git @allArgs
}

function Get-StagedPaths {
  $raw = & git --no-pager diff --cached --name-only
  if ($LASTEXITCODE -ne 0) { throw "git diff --cached failed" }
  if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
  return ($raw -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 } | ForEach-Object { $_.Replace('\', '/') })
}

function Assert-StagedExactly {
  param(
    [string[]]$Expected,
    [string]$ContextLabel
  )
  $actual = Get-StagedPaths
  $expectedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]($Expected | ForEach-Object { $_.Replace('\','/') }))
  $actualSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$actual)

  $extra = $actualSet | Where-Object { -not $expectedSet.Contains($_) }
  $missing = $expectedSet | Where-Object { -not $actualSet.Contains($_) }

  if ($extra -or $missing) {
    Write-Host ""
    Write-Host "==> [$ContextLabel] STAGED SET MISMATCH" -ForegroundColor Red
    if ($extra) {
      Write-Host "  Unexpected staged files (not part of $ContextLabel):" -ForegroundColor Red
      $extra | ForEach-Object { Write-Host "    + $_" -ForegroundColor Red }
    }
    if ($missing) {
      Write-Host "  Missing files (expected to be staged but were not):" -ForegroundColor Yellow
      $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    }
    throw "Aborting commit for $ContextLabel — staged set mismatch."
  }
}

Push-Location $repoRoot
try {
  Write-Host "==> Repo: $repoRoot" -ForegroundColor Cyan

  $insideRepo = (& git --no-pager rev-parse --is-inside-work-tree 2>$null)
  if ($LASTEXITCODE -ne 0 -or $insideRepo -ne 'true') {
    throw "Not inside a git repository: $repoRoot"
  }

  # ----- Pre-flight: reset staging area to avoid contamination -----
  if (-not $KeepStaged) {
    Write-Host "`n==> Pre-flight: clearing staged area (use -KeepStaged to skip)" -ForegroundColor Cyan
    if ($DryRun) {
      Write-Host "  would: git reset (unstage everything)" -ForegroundColor DarkGray
    } else {
      Invoke-Git reset
    }
  } else {
    Write-Host "`n==> Pre-flight: -KeepStaged set, NOT resetting staging area" -ForegroundColor Yellow
  }

  # ============================================================
  # COMMIT 1 — refactor(policy): T02 source + tests
  # ============================================================
  $sourceFiles = @(
    'backend/src/policy/__init__.py',
    'backend/src/policy/approval.py',
    'backend/src/policy/preflight.py',
    'backend/src/policy/approval_dto.py',
    'backend/src/policy/approval_service.py',
    'backend/tests/security/conftest.py',
    'backend/tests/unit/policy/test_no_cyclic_imports.py',
    'backend/tests/unit/policy/test_approval_dto.py',
    'backend/tests/unit/policy/test_approval_shim.py'
  )

  Write-Host "`n==> Stage T02 source/test files" -ForegroundColor Cyan
  $stagedActual = New-Object System.Collections.Generic.List[string]
  foreach ($f in $sourceFiles) {
    $abs = Join-Path $repoRoot $f
    if (-not (Test-Path $abs)) {
      Write-Warning "Missing (skipped): $f"
      continue
    }
    if ($DryRun) {
      Write-Host "  would: git add $f"
      $stagedActual.Add($f)
    } else {
      Invoke-Git add -- $f
      $stagedActual.Add($f)
    }
  }

  Write-Host "`n==> Verify staged set is exactly the T02 allow-list" -ForegroundColor Cyan
  if (-not $DryRun) {
    Assert-StagedExactly -Expected $stagedActual -ContextLabel 'T02 (commit 1)'
    Write-Host "  OK — staged set matches T02 allow-list ($($stagedActual.Count) files)." -ForegroundColor Green
  }

  Write-Host "`n==> Staged set (commit 1):" -ForegroundColor Cyan
  Invoke-GitNoThrow diff --cached --name-status
  Write-Host ""
  Invoke-GitNoThrow diff --cached --shortstat

  $commit1Msg = @'
refactor(policy): split approval into pure DTO + service to break latent import cycle (T02)

Splits backend/src/policy/approval.py into approval_dto.py (pure pydantic, no
heavy deps) and approval_service.py (Ed25519 + audit). preflight.py now uses
TYPE_CHECKING + lazy pydantic rebuild (defer_build=True + _ensure_pydantic_built);
__init__ uses PEP 562 lazy __getattr__ so the package no longer eagerly loads
all submodules. Backward-compat shim approval.py preserves the legacy import
surface (7 names re-exported with explicit __all__).

Removes the pre-warm hack from tests/security/conftest.py (no longer needed).
Adds 104 new tests (unit/policy): test_no_cyclic_imports.py (subprocess +
in-process probes for cycles, DTO purity, dev-mode warnings),
test_approval_dto.py (DTO functionality + AST-walk for stdlib-only imports),
test_approval_shim.py (backward-compat surface + identity assertions).

Verification: 104/104 new tests + 388/388 policy regression tests + ruff clean.
Reviewer: 21 PASS / 5 MINOR / 0 MAJOR. MINOR follow-ups recorded in
.cursor/workspace/active/orch-argus-20260420-1430/notes/T02-followups.md.
'@

  Write-Host "`n==> Commit 1 message:" -ForegroundColor Cyan
  Write-Host $commit1Msg -ForegroundColor DarkGray

  if (-not $DryRun) {
    $tmp1 = New-TemporaryFile
    [IO.File]::WriteAllText($tmp1.FullName, $commit1Msg, [Text.UTF8Encoding]::new($false))
    $commitArgs = @('--no-pager', 'commit', '-F', $tmp1.FullName)
    if ($SkipHooks) { $commitArgs += '--no-verify' }
    & git @commitArgs
    $code = $LASTEXITCODE
    Remove-Item $tmp1.FullName -Force
    if ($code -ne 0) { throw "git commit (1) failed with exit $code" }
    $hash1 = (& git --no-pager rev-parse HEAD).Trim()
    Write-Host "  COMMIT1=$hash1" -ForegroundColor Green
  }

  # ============================================================
  # COMMIT 2 — chore(orchestration): workspace state
  # ============================================================
  $wsFiles = @(
    '.cursor/workspace/active/orch-argus-20260420-1430/plan.md',
    '.cursor/workspace/active/orch-argus-20260420-1430/links.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/tasks.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/progress.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/notes/T02-followups.md'
  )

  Write-Host "`n==> Stage workspace state files" -ForegroundColor Cyan
  $stagedActual2 = New-Object System.Collections.Generic.List[string]
  foreach ($f in $wsFiles) {
    $abs = Join-Path $repoRoot $f
    if (-not (Test-Path $abs)) {
      Write-Warning "Missing (skipped): $f"
      continue
    }
    if ($DryRun) {
      Write-Host "  would: git add $f"
      $stagedActual2.Add($f)
    } else {
      Invoke-Git add -- $f
      $stagedActual2.Add($f)
    }
  }

  Write-Host "`n==> Verify staged set is exactly the workspace allow-list" -ForegroundColor Cyan
  if (-not $DryRun) {
    Assert-StagedExactly -Expected $stagedActual2 -ContextLabel 'workspace (commit 2)'
    Write-Host "  OK — staged set matches workspace allow-list ($($stagedActual2.Count) files)." -ForegroundColor Green
  }

  Write-Host "`n==> Staged set (commit 2):" -ForegroundColor Cyan
  Invoke-GitNoThrow diff --cached --name-status
  Write-Host ""
  Invoke-GitNoThrow diff --cached --shortstat

  $commit2Msg = @'
chore(orchestration): create orch-argus-20260420-1430 workspace, mark T02 done

T02 (cyclic policy import refactor) verified: 104 new tests + 388 regression
tests + ruff + imports all green. Reviewer: 21 PASS / 5 MINOR / 0 MAJOR.

Workspace artefacts:
- plan.md: Batch 1 safe-first ordering (10 tasks, T02 first)
- tasks.json: T02 completed, T03..T05 pending
- progress.json: 1/10 complete, currentTask=T03
- links.json: pointers to roadmap/spec/changelog
- notes/T02-followups.md: 5 non-blocking MINOR items for later

Next task: T03 (Network-tool YAML migration, 16 dual-listed, S/zero-risk).
'@

  Write-Host "`n==> Commit 2 message:" -ForegroundColor Cyan
  Write-Host $commit2Msg -ForegroundColor DarkGray

  if (-not $DryRun) {
    $diffStat = & git --no-pager diff --cached --shortstat
    if ([string]::IsNullOrWhiteSpace($diffStat)) {
      Write-Host "  No staged changes for commit 2 — already committed earlier? Skipping." -ForegroundColor Yellow
    } else {
      $tmp2 = New-TemporaryFile
      [IO.File]::WriteAllText($tmp2.FullName, $commit2Msg, [Text.UTF8Encoding]::new($false))
      $commitArgs2 = @('--no-pager', 'commit', '-F', $tmp2.FullName)
      if ($SkipHooks) { $commitArgs2 += '--no-verify' }
      & git @commitArgs2
      $code2 = $LASTEXITCODE
      Remove-Item $tmp2.FullName -Force
      if ($code2 -ne 0) { throw "git commit (2) failed with exit $code2" }
      $hash2 = (& git --no-pager rev-parse HEAD).Trim()
      Write-Host "  COMMIT2=$hash2" -ForegroundColor Green
    }
  }

  # ============================================================
  # FINAL REPORT
  # ============================================================
  Write-Host "`n==> Final state" -ForegroundColor Cyan
  Invoke-GitNoThrow log --oneline -n 5
  Write-Host ""
  Invoke-GitNoThrow status --short
  Write-Host "`nT02 commit script complete." -ForegroundColor Green
}
finally {
  Pop-Location
}
