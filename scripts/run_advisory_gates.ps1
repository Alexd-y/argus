# T08 — run advisory SCA/SAST gates via the local DoD meta-runner (Windows).
# Same surface as .github/workflows/advisory-gates.yml (informational locally).
$ErrorActionPreference = "Stop"
$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RootDir
python scripts/argus_validate.py --only-advisory @args
