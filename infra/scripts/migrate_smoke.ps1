# infra/scripts/migrate_smoke.ps1
# ──────────────────────────────────────────────────────────────────────────────
# Windows-friendly equivalent of migrate_smoke.sh.
# Invoke from the repo root:
#   $env:DATABASE_URL = "postgresql+psycopg2://argus:argus@localhost:5432/argus_test"
#   .\infra\scripts\migrate_smoke.ps1
$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$BackendDir = Join-Path $RootDir "backend"
$PythonBin = $env:PYTHON_BIN
if (-not $PythonBin) {
    $PythonBin = Join-Path $BackendDir ".venv\Scripts\python.exe"
}
if (-not (Test-Path $PythonBin)) {
    $PythonBin = (Get-Command python).Source
}

if (-not $env:DATABASE_URL) {
    Write-Error "DATABASE_URL is required"
    exit 2
}

Push-Location $BackendDir
try {
    Write-Host "==> migrate_smoke: upgrade head (round 1)"
    & $PythonBin -m alembic upgrade head
    if ($LASTEXITCODE -ne 0) { throw "alembic upgrade failed" }

    $Snap1 = New-TemporaryFile
    $Snap2 = New-TemporaryFile

    try {
        Write-Host "==> migrate_smoke: snapshot S1 → $Snap1"
        & $PythonBin -m scripts.dump_alembic_schema | Set-Content -Path $Snap1 -NoNewline
        if ($LASTEXITCODE -ne 0) { throw "dump_alembic_schema (S1) failed" }

        Write-Host "==> migrate_smoke: downgrade -5"
        & $PythonBin -m alembic downgrade -5
        if ($LASTEXITCODE -ne 0) { throw "alembic downgrade -5 failed" }

        Write-Host "==> migrate_smoke: upgrade head (round 2)"
        & $PythonBin -m alembic upgrade head
        if ($LASTEXITCODE -ne 0) { throw "alembic upgrade (round 2) failed" }

        Write-Host "==> migrate_smoke: snapshot S2 → $Snap2"
        & $PythonBin -m scripts.dump_alembic_schema | Set-Content -Path $Snap2 -NoNewline
        if ($LASTEXITCODE -ne 0) { throw "dump_alembic_schema (S2) failed" }

        $Hash1 = (Get-FileHash -Algorithm SHA256 $Snap1).Hash
        $Hash2 = (Get-FileHash -Algorithm SHA256 $Snap2).Hash
        Write-Host "==> migrate_smoke: S1 sha256=$Hash1"
        Write-Host "==> migrate_smoke: S2 sha256=$Hash2"

        if ($Hash1 -ne $Hash2) {
            $diff = Compare-Object (Get-Content $Snap1) (Get-Content $Snap2)
            $diff | Format-Table -AutoSize | Out-String | Write-Host
            throw "schema drift detected between round 1 and round 2"
        }

        Write-Host "==> migrate_smoke: OK (round-trip schema diff = 0)"
    }
    finally {
        Remove-Item -ErrorAction SilentlyContinue $Snap1
        Remove-Item -ErrorAction SilentlyContinue $Snap2
    }
}
finally {
    Pop-Location
}
