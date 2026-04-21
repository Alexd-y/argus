#requires -Version 5.1
<#
.SYNOPSIS
    Commit T10 (E2E multi-target vuln smoke: DVWA + WebGoat + Juice Shop).

.DESCRIPTION
    Single commit: compose, Playwright, workflow, docs, ISS + orchestration state.

.PARAMETER DryRun
    Print what would be staged + committed; do NOT run git add/commit.

.EXAMPLE
    .\scripts\orchestration\commit_T10.ps1 -DryRun

.NOTES
    Git pager: $env:GIT_PAGER='cat', $env:PAGER='cat'; Invoke-Git prepends --no-pager on every call.
#>

[CmdletBinding()]
param(
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$env:GIT_PAGER = 'cat'
$env:PAGER = 'cat'

function Invoke-Git {
    param([Parameter(Mandatory)][string[]]$Args)
    $allArgs = @('--no-pager') + $Args
    $output = & git @allArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git command failed: $($Args -join ' ')"
    }
    return $output
}

$repoRoot = (Invoke-Git -Args @('rev-parse', '--show-toplevel')).Trim()
Set-Location $repoRoot

if (-not $DryRun) {
    Invoke-Git -Args @('reset') | Out-Null
}

$t10Files = @(
    'infra/docker-compose.vuln-targets.yml',
    'infra/e2e-vuln-targets.md',
    'Frontend/playwright.config.ts',
    'Frontend/tests/e2e/vuln-targets/vuln-target-smoke.spec.ts',
    'Frontend/package.json',
    '.github/workflows/e2e-vuln-target-smoke.yml',
    '.github/workflows/e2e-full-scan.yml',
    'docs/e2e-testing.md',
    'ai_docs/develop/issues/ISS-cycle6-carry-over.md',
    '.cursor/workspace/active/orch-argus-20260420-1430/tasks.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/progress.json',
    'scripts/orchestration/commit_T10.ps1'
)

Write-Host "==> Staging T10 ($($t10Files.Count) files)"
foreach ($f in $t10Files) {
    $abs = Join-Path $repoRoot ($f -replace '/', '\')
    if (-not (Test-Path $abs)) {
        throw "Missing $f"
    }
    if ($DryRun) {
        Write-Host "  [dry-run] git add -- $f"
    } else {
        Invoke-Git -Args @('add', '--', $f) | Out-Null
    }
}

$msg = @"
test(e2e): add DVWA and WebGoat to target matrix (T10)

- infra/docker-compose.vuln-targets.yml: pinned lab images (tag@sha256), profiles
- Playwright vuln-smoke project + smoke spec (E2E_VULN_TARGET/BASE_URL)
- GHA e2e-vuln-target-smoke matrix; continue-on-error for dvwa/webgoat
- docs/e2e-testing.md §11, infra/e2e-vuln-targets.md; ISS item 5 RESOLVED

Refs T10.
"@

if ($DryRun) {
    Write-Host $msg
    exit 0
}

$msg | Out-File -FilePath "$env:TEMP\argus_t10_msg.txt" -Encoding utf8 -NoNewline
Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t10_msg.txt") | Out-Null
Remove-Item "$env:TEMP\argus_t10_msg.txt" -Force -ErrorAction SilentlyContinue
Write-Host "Done: $(Invoke-Git -Args @('rev-parse', '--short', 'HEAD'))" -ForegroundColor Green
