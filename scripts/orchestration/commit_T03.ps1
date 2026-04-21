#requires -Version 5.1
<#
.SYNOPSIS
    Commit T03 (ARG-058 Network-tool YAML migration) to the ARGUS repo.

.DESCRIPTION
    Hardened commit script (mirrors commit_T02.ps1 v2 safety pattern):
    - Disables git pager to avoid interactive hangs.
    - Resets the staging area at start to avoid contamination from prior runs.
    - Stages an explicit allow-list of files; assert-staged-exactly check after each step.
    - Two atomic commits:
        1. Source/registry/test changes (16 YAMLs + manifest + tests + docs).
        2. Workspace-state files (.cursor/workspace/active/orch-argus-.../...).

.PARAMETER DryRun
    Print what would be staged + committed; do NOT actually run git add/commit.

.PARAMETER KeepStaged
    Skip the initial `git reset` (only use if you have intentionally pre-staged files).

.PARAMETER SignAfterCommit
    After commit 1 succeeds, run `python backend/scripts/tools_sign.py --sign` and amend
    the SIGNATURES file into the same commit. Requires the gitignored
    `backend/config/tools/_keys/dev_signing.ed25519.priv` to exist.
    NOTE: amending is safe here because commit 1 will not have been pushed yet.

.EXAMPLE
    # Preview what would happen (RECOMMENDED FIRST RUN):
    .\scripts\orchestration\commit_T03.ps1 -DryRun

.EXAMPLE
    # Real commit:
    .\scripts\orchestration\commit_T03.ps1

.EXAMPLE
    # Real commit + re-sign + amend SIGNATURES into commit 1:
    .\scripts\orchestration\commit_T03.ps1 -SignAfterCommit

.NOTES
    Git pager: $env:GIT_PAGER='cat', $env:PAGER='cat'; every git invocation goes through
    Invoke-Git which prepends --no-pager (no interactive ':' pager).
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$KeepStaged,
    [switch]$SignAfterCommit
)

$ErrorActionPreference = 'Stop'
$env:GIT_PAGER = 'cat'  # Prevent any git pager from hanging the script.
$env:PAGER = 'cat'

# --------------------------------------------------------------------------
# Helpers
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
# 0. Sanity: are we in the right repo?
# --------------------------------------------------------------------------

$repoRoot = (Invoke-Git -Args @('rev-parse', '--show-toplevel')).Trim()
Write-Host "==> Repo: $repoRoot"

if (-not (Test-Path "$repoRoot\backend\config\tools\snmpwalk.yaml")) {
    throw "Sanity check failed: backend/config/tools/snmpwalk.yaml not found at $repoRoot. Are you in ARGUS root?"
}

Set-Location $repoRoot

# --------------------------------------------------------------------------
# 1. Reset staging to a known state
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
# 2. Allow-list — files that belong to commit 1 (T03 source/registry/tests)
# --------------------------------------------------------------------------

$migratedTools = @(
    'bloodhound_python', 'crackmapexec', 'evil_winrm', 'ike_scan',
    'impacket_examples', 'impacket_secretsdump', 'kerbrute', 'ldapsearch',
    'mongodb_probe', 'ntlmrelayx', 'onesixtyone', 'redis_cli_probe',
    'responder', 'smbclient', 'snmp_check', 'snmpwalk'
)

$t03Files = New-Object System.Collections.Generic.List[string]

# 16 YAMLs
foreach ($tool in $migratedTools) {
    $null = $t03Files.Add("backend/config/tools/$tool.yaml")
}

# Manifest + generator + doc + ISS
$null = $t03Files.Add('infra/sandbox/images/tool_to_package.json')
$null = $t03Files.Add('backend/scripts/docs_tool_catalog.py')
$null = $t03Files.Add('docs/tool-catalog.md')
$null = $t03Files.Add('ai_docs/develop/issues/ISS-cycle6-carry-over.md')

# New + modified test files
$null = $t03Files.Add('backend/tests/test_arg058_dual_listed_migration.py')
$null = $t03Files.Add('backend/tests/conftest.py')
$null = $t03Files.Add('backend/tests/unit/sandbox/test_yaml_arg019_semantics.py')
$null = $t03Files.Add('backend/tests/unit/sandbox/test_yaml_oast_auth_hash_semantics.py')
$null = $t03Files.Add('backend/tests/integration/sandbox/test_tool_catalog_load.py')
$null = $t03Files.Add('backend/tests/integration/sandbox/test_arg017_end_to_end.py')

# --------------------------------------------------------------------------
# 3. Pre-flight: verify every file in allow-list exists and is modified/new
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "==> Pre-flight: checking $($t03Files.Count) files exist + have changes"

$missing = @()
$unchanged = @()
foreach ($rel in $t03Files) {
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
    Write-Host "[FATAL] Missing files (worker did not deliver?):" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" }
    throw "missing files in allow-list"
}

if ($unchanged) {
    Write-Host ""
    Write-Host "[WARN] Files in allow-list with no git changes:" -ForegroundColor Yellow
    $unchanged | ForEach-Object { Write-Host "  $_" }
    Write-Host "These will not be in the commit. Either there's no work to do for them," -ForegroundColor Yellow
    Write-Host "or you committed them previously. Inspect 'git log -- <path>' if surprised." -ForegroundColor Yellow
    Write-Host ""
    # Filter unchanged files out of the staging list so the assert-staged-exactly check passes.
    $t03Files = [System.Collections.Generic.List[string]]@($t03Files | Where-Object { $_ -notin $unchanged })
}

# --------------------------------------------------------------------------
# 4. Stage commit 1 (T03 source/registry/tests)
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "==> Stage T03 source/registry/test files ($($t03Files.Count) files)"
foreach ($f in $t03Files) {
    Stage-File -Path $f
}

if (-not $DryRun) {
    Assert-StagedExactly -Expected $t03Files -ContextLabel 'T03 (commit 1)'
}

# --------------------------------------------------------------------------
# 5. Commit 1
# --------------------------------------------------------------------------

$commit1Body = @"
chore(tools): migrate 16 dual-listed YAMLs from argus-kali-web to argus-kali-network (T03 / ARG-058)

Move the 16 protocol-exploitation tools (BloodHound, CrackMapExec, evil-winrm,
IKE-scan, impacket suite, kerbrute, LDAP, Mongo, ntlmrelayx, onesixtyone,
Redis, Responder, SMB, SNMP) off the shared argus-kali-web profile (91 -> 75)
into the dedicated argus-kali-network profile (0 -> 16), eliminating the
dual-listing introduced in ARG-048 (Cycle 5).

- backend/config/tools/<16>.yaml: image flipped argus-kali-web:latest -> argus-kali-network:latest (no other field touched)
- infra/sandbox/images/tool_to_package.json: 16 tool_ids removed from argus-kali-web.tools; schema_version bumped 1.1.0 -> 1.2.0; per-profile purpose strings updated
- backend/scripts/docs_tool_catalog.py + docs/tool-catalog.md: image-coverage section regenerated synchronously (totals 157)
- backend/tests/test_arg058_dual_listed_migration.py (NEW): 7 invariant tests / 37 cases pinning image, field-count, no-dual-listing, set membership, schema bump, ISS marker
- backend/tests/conftest.py: new module added to _OFFLINE_FILE_NAMES
- backend/tests/unit/sandbox/test_yaml_{arg019,oast_auth_hash}_semantics.py: IMAGE_BY_TOOL refactored to per-tool maps with lock-step guards
- backend/tests/integration/sandbox/test_{tool_catalog_load,arg017_end_to_end}.py: per-tool image maps with lock-step guards
- ai_docs/develop/issues/ISS-cycle6-carry-over.md: ARG-058 marked RESOLVED with deferred re-sign caveat

BREAKING-DEPLOY: SIGNATURES file holds stale hashes for the 16 migrated YAMLs.
ToolRegistry.load() is fail-closed and WILL refuse to start the backend until
``python backend/scripts/tools_sign.py --sign`` is run with the gitignored
Ed25519 private key. Signature-aware integration tests will be skipped/red
until then. Tracked in ai_docs/develop/issues/ISS-cycle6-carry-over.md.

Refs ARG-058, T03.
"@

if ($DryRun) {
    Write-Host ""
    Write-Host "==> [dry-run] Would commit with message:" -ForegroundColor DarkGray
    Write-Host $commit1Body -ForegroundColor DarkGray
} else {
    Write-Host ""
    Write-Host "==> Commit 1 (T03 source/registry/tests)"
    $commit1Body | Out-File -FilePath "$env:TEMP\argus_t03_msg.txt" -Encoding utf8 -NoNewline
    Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t03_msg.txt") | Out-Null
    Remove-Item "$env:TEMP\argus_t03_msg.txt" -Force -ErrorAction SilentlyContinue
    Write-Host "  + Commit 1 created: $((Invoke-Git -Args @('rev-parse', '--short', 'HEAD')).Trim())" -ForegroundColor Green
}

# --------------------------------------------------------------------------
# 5.b (optional) Re-sign + amend SIGNATURES into commit 1
# --------------------------------------------------------------------------

if ($SignAfterCommit) {
    Write-Host ""
    Write-Host "==> Re-signing 16 YAMLs (Ed25519)"
    $privKey = Join-Path $repoRoot 'backend\config\tools\_keys\dev_signing.ed25519.priv'
    if (-not (Test-Path $privKey)) {
        Write-Host "[FATAL] Private key not found: $privKey" -ForegroundColor Red
        Write-Host "Generate first: python backend/scripts/tools_sign.py --generate-keys --out backend/config/tools/_keys" -ForegroundColor Yellow
        throw "missing dev_signing.ed25519.priv"
    }

    if ($DryRun) {
        Write-Host "  [dry-run] python backend/scripts/tools_sign.py --sign ..." -ForegroundColor DarkGray
    } else {
        & python "backend\scripts\tools_sign.py" --sign `
            --key       "backend\config\tools\_keys\dev_signing.ed25519.priv" `
            --tools-dir "backend\config\tools" `
            --out       "backend\config\tools\SIGNATURES"
        if ($LASTEXITCODE -ne 0) { throw "tools_sign.py --sign failed" }

        # Verify
        & python "backend\scripts\tools_sign.py" --verify `
            --tools-dir   "backend\config\tools" `
            --signatures  "backend\config\tools\SIGNATURES" `
            --keys-dir    "backend\config\tools\_keys"
        if ($LASTEXITCODE -ne 0) { throw "tools_sign.py --verify failed" }

        # Amend SIGNATURES into commit 1
        Invoke-Git -Args @('add', '--', 'backend/config/tools/SIGNATURES') | Out-Null
        Assert-StagedExactly -Expected @('backend/config/tools/SIGNATURES') -ContextLabel 'SIGNATURES (amend)'
        Invoke-Git -Args @('commit', '--amend', '--no-edit') | Out-Null
        Write-Host "  + SIGNATURES amended into commit 1" -ForegroundColor Green
    }
}

# --------------------------------------------------------------------------
# 6. Stage commit 2 (workspace state)
# --------------------------------------------------------------------------

$workspaceFiles = @(
    '.cursor/workspace/active/orch-argus-20260420-1430/tasks.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/progress.json',
    '.cursor/workspace/active/orch-argus-20260420-1430/notes/T03-followups.md',
    'scripts/orchestration/commit_T03.ps1'
)

# Only include files that actually exist + have changes
$workspaceStage = New-Object System.Collections.Generic.List[string]
foreach ($rel in $workspaceFiles) {
    $abs = Join-Path $repoRoot ($rel -replace '/', '\')
    if (-not (Test-Path $abs)) {
        Write-Host "  (skipping $rel — file does not exist)" -ForegroundColor DarkGray
        continue
    }
    $statusLine = (Invoke-Git -Args @('status', '--porcelain', '--', $rel)) -join "`n"
    if ($statusLine.Trim()) {
        $null = $workspaceStage.Add($rel)
    } else {
        Write-Host "  (skipping $rel — no changes)" -ForegroundColor DarkGray
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
chore(workspace): mark T03 completed in orchestration state (orch-argus-20260420-1430)

- tasks.json: T03 status -> completed; deliverables, lock-step guards, deferred re-sign step recorded
- progress.json: completedTasks 1 -> 2; currentTask T03 -> T06; T03 commit recorded as ready
- notes/T03-followups.md (NEW): operator re-sign runbook + 5 minor follow-ups + audit trail
- scripts/orchestration/commit_T03.ps1 (NEW): hardened commit script (mirrors T02 v2 safety pattern)

Refs T03, ARG-058, orchestration:orch-argus-20260420-1430.
"@

if ($DryRun) {
    Write-Host ""
    Write-Host "==> [dry-run] Would commit with message:" -ForegroundColor DarkGray
    Write-Host $commit2Body -ForegroundColor DarkGray
} else {
    Write-Host ""
    Write-Host "==> Commit 2 (workspace state)"
    $commit2Body | Out-File -FilePath "$env:TEMP\argus_t03_ws_msg.txt" -Encoding utf8 -NoNewline
    Invoke-Git -Args @('commit', '-F', "$env:TEMP\argus_t03_ws_msg.txt") | Out-Null
    Remove-Item "$env:TEMP\argus_t03_ws_msg.txt" -Force -ErrorAction SilentlyContinue
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
if (-not $SignAfterCommit) {
    Write-Host ""
    Write-Host "[!] SIGNATURES file is now stale. Backend will fail-closed until you re-sign." -ForegroundColor Yellow
    Write-Host "    Run: .\scripts\orchestration\commit_T03.ps1 -SignAfterCommit  (re-runs the script with re-sign + amend)" -ForegroundColor Yellow
    Write-Host "    OR:  python backend\scripts\tools_sign.py --sign --key backend\config\tools\_keys\dev_signing.ed25519.priv --tools-dir backend\config\tools --out backend\config\tools\SIGNATURES" -ForegroundColor Yellow
    Write-Host "         then commit backend/config/tools/SIGNATURES separately." -ForegroundColor Yellow
}
