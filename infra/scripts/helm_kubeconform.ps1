# infra/scripts/helm_kubeconform.ps1
# ──────────────────────────────────────────────────────────────────────────────
# T07 — Helm chart kubeconform schema validation (Windows-friendly twin of
# helm_kubeconform.sh). Same semantics, same exit-code contract:
#   0 → all overlays valid; 2 → tool missing; 3 → at least one schema failure.
#
# Usage:
#   pwsh infra/scripts/helm_kubeconform.ps1 [-KubeVersion 1.31.0] [-Output text]
#   $env:KUBE_VERSION="1.27.0"; pwsh infra/scripts/helm_kubeconform.ps1
[CmdletBinding()]
param(
    [string] $KubeVersion = $(if ($env:KUBE_VERSION) { $env:KUBE_VERSION } else { "1.29.0" }),
    [ValidateSet("text", "json", "tap", "pretty", "junit")]
    [string] $Output = $(if ($env:KUBECONFORM_OUTPUT) { $env:KUBECONFORM_OUTPUT } else { "json" }),
    [string] $ReleaseName = $(if ($env:RELEASE_NAME) { $env:RELEASE_NAME } else { "argus" })
)

$ErrorActionPreference = "Stop"

$RootDir  = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$ChartDir = Join-Path $RootDir "infra\helm\argus"

# Fake-but-syntactically-valid digests used for render only — never deployed.
$FakeDigest = "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
$ProdDigestOverrides = @(
    "--set", "image.backend.digest=$FakeDigest",
    "--set", "image.celery.digest=$FakeDigest",
    "--set", "image.frontend.digest=$FakeDigest",
    "--set", "image.mcp.digest=$FakeDigest"
)

$CrdSchemaLocation = 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
$SkipKinds = "CustomResourceDefinition"

# Pre-flight: required binaries on PATH.
if (-not (Get-Command helm -ErrorAction SilentlyContinue)) {
    Write-Error "helm not on PATH"
    exit 2
}
if (-not (Get-Command kubeconform -ErrorAction SilentlyContinue)) {
    Write-Error "kubeconform not on PATH (https://github.com/yannh/kubeconform#installation)"
    exit 2
}

Write-Host "==> helm_kubeconform: chart=$ChartDir"
Write-Host "==> helm_kubeconform: kubernetes-version=$KubeVersion"
Write-Host "==> helm_kubeconform: output-format=$Output"
Write-Host "==> helm_kubeconform: helm $((helm version --short 2>$null) -join ' ')"
Write-Host "==> helm_kubeconform: kubeconform $((kubeconform -v 2>&1 | Select-Object -First 1))"

Write-Host "==> helm_kubeconform: dependency update"
helm dependency update $ChartDir
if ($LASTEXITCODE -ne 0) { throw "helm dependency update failed (exit $LASTEXITCODE)" }

$Overlays = @("dev", "staging", "prod")
$Failed = New-Object System.Collections.Generic.List[string]

foreach ($overlay in $Overlays) {
    $valuesFile = Join-Path $ChartDir "values-$overlay.yaml"
    if (-not (Test-Path $valuesFile)) {
        Write-Warning "values-$overlay.yaml not found at $valuesFile - skipping"
        continue
    }

    Write-Host ""
    Write-Host "──────────────────────────────────────────────────────────────────"
    Write-Host "==> helm_kubeconform: validating overlay '$overlay' (k8s $KubeVersion)"
    Write-Host "──────────────────────────────────────────────────────────────────"

    $templateArgs = @("template", $ReleaseName, $ChartDir, "-f", $valuesFile)
    if ($overlay -eq "prod") {
        $templateArgs += $ProdDigestOverrides
    }

    # Render to a string first; capturing helm's exit code separately is the
    # only Windows-portable way to detect a failed render before piping.
    $rendered = & helm @templateArgs
    $helmExit = $LASTEXITCODE
    if ($helmExit -ne 0) {
        Write-Warning "helm template exited $helmExit for overlay '$overlay'"
        $Failed.Add("$overlay(helm:$helmExit)")
        continue
    }

    $kubeconformArgs = @(
        "--strict",
        "--summary",
        "--output", $Output,
        "--kubernetes-version", $KubeVersion,
        "--skip", $SkipKinds,
        "--schema-location", "default",
        "--schema-location", $CrdSchemaLocation,
        "-"
    )
    $rendered | & kubeconform @kubeconformArgs
    $kubeconformExit = $LASTEXITCODE
    if ($kubeconformExit -ne 0) {
        Write-Warning "kubeconform exited $kubeconformExit for overlay '$overlay'"
        $Failed.Add("$overlay(kubeconform:$kubeconformExit)")
        continue
    }
    Write-Host "PASS: overlay '$overlay' validated against k8s $KubeVersion"
}

Write-Host ""
Write-Host "──────────────────────────────────────────────────────────────────"
if ($Failed.Count -eq 0) {
    Write-Host "==> helm_kubeconform: OK (all overlays valid against k8s $KubeVersion)"
    exit 0
}

Write-Error ("helm_kubeconform: FAILED overlays: " + ($Failed -join ", "))
exit 3
