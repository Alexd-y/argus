# infra/scripts/helm_lint.ps1
# ──────────────────────────────────────────────────────────────────────────────
# Windows-friendly equivalent of helm_lint.sh.
$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$ChartDir = Join-Path $RootDir "infra\helm\argus"

$FakeDigest = "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
$DigestOverrides = @(
    "--set", "image.backend.digest=$FakeDigest",
    "--set", "image.celery.digest=$FakeDigest",
    "--set", "image.frontend.digest=$FakeDigest",
    "--set", "image.mcp.digest=$FakeDigest"
)

if (-not (Get-Command helm -ErrorAction SilentlyContinue)) {
    Write-Error "helm not on PATH"
    exit 2
}

Write-Host "==> helm_lint: dependency update"
helm dependency update $ChartDir
if ($LASTEXITCODE -ne 0) { throw "helm dependency update failed" }

foreach ($envName in @("dev", "staging", "prod")) {
    Write-Host "==> helm_lint: lint values-$envName.yaml"
    $valuesFile = Join-Path $ChartDir "values-$envName.yaml"
    if ($envName -eq "prod") {
        helm lint $ChartDir -f $valuesFile @DigestOverrides
    }
    else {
        helm lint $ChartDir -f $valuesFile
    }
    if ($LASTEXITCODE -ne 0) { throw "helm lint $envName failed" }
}

Write-Host "==> helm_lint: template render values-prod.yaml"
helm template argus $ChartDir -f (Join-Path $ChartDir "values-prod.yaml") @DigestOverrides | Out-Null
if ($LASTEXITCODE -ne 0) { throw "helm template prod failed" }

if (Get-Command kubeconform -ErrorAction SilentlyContinue) {
    Write-Host "==> helm_lint: kubeconform --strict"
    $rendered = helm template argus $ChartDir -f (Join-Path $ChartDir "values-prod.yaml") @DigestOverrides
    $rendered | kubeconform --strict --summary --skip CustomResourceDefinition `
        --schema-location default `
        --schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' `
        -
    if ($LASTEXITCODE -ne 0) { throw "kubeconform validation failed" }
}
else {
    Write-Warning "kubeconform not on PATH - skipping CRD schema validation"
}

Write-Host "==> helm_lint: OK"
