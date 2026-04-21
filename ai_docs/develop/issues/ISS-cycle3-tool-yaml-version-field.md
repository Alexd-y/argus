# ISS — Cycle 3 Tool YAML `version:` field gap (ARG-026 follow-up)

**Issue ID:** ISS-cycle3-tool-yaml-version-field
**Owner:** Backend / Tool catalog
**Source task:** ARG-026 (`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` lines 312-355)
**Status:** Open — deferred to Cycle 4
**Priority:** LOW
**Date filed:** 2026-04-19

---

## Context

ARG-026 task brief said:

> Pinned versions live in those YAMLs (`version` field). Use them as the
> source of truth.

Per-tool YAMLs under `backend/config/tools/*.yaml` (157 files) currently
do **not** carry a `version:` field. A spot-check across all relevant
profiles (web, cloud, browser, full):

```powershell
# from repo root
Get-Content backend/config/tools/nuclei.yaml      | Select-String "^version"  # → no match
Get-Content backend/config/tools/trivy.yaml       | Select-String "^version"  # → no match
Get-Content backend/config/tools/playwright.yaml  | Select-String "^version"  # → no match
```

The Pydantic descriptor in `backend/src/sandbox/tool_registry.py`
(`ToolDescriptor` model) does not expose a `version: str | None` field
either, so even if a YAML did declare a version, it would be silently
discarded at load time.

## Why this matters

ARG-026 needed pinned tool versions per image. Without a `version:` field
in the catalog, the version pin had to live **inside** each Dockerfile
(see `sandbox/images/argus-kali-{web,cloud,browser,full}/Dockerfile` and
the table in `docs/sandbox-images.md` §1.1).

That works but creates a **dual source of truth**:

* Catalog YAML says: "use tool X, command-template `<binary> {target}`".
* Dockerfile says: "binary X is pinned to v1.2.3".

If the YAML's `command_template` ever drifts from the Dockerfile's pinned
version (e.g. someone bumps `nuclei` in the Dockerfile from `3.7.1` to
`3.8.0` and the YAML's flag set lags), the sandbox driver has no way to
detect it. We'll only find out at runtime when nuclei prints
"unrecognised flag".

## Proposed fix (Cycle 4)

1. Add `version: str` (semver string, optional, default `null`) to
   `ToolDescriptor` in `backend/src/sandbox/tool_registry.py`. When
   present, the value is treated as informational metadata; the loader
   does not enforce it at load time.

2. Backfill the catalog YAMLs with the versions that match each
   Dockerfile pin. Sort order: tools that already have command-template
   flags tied to a specific version (`nuclei -t`, `trivy --severity`)
   first; reformatters / passive scanners last.

3. Add a sandbox driver pre-flight check that compares
   `descriptor.version` against the `argus.image.version` label baked into
   the image at build time (set by `--build-arg ARGUS_IMAGE_VERSION=...`
   in `infra/scripts/build_images.sh`). On mismatch, log a structured
   warning (`event: tool_version_mismatch`) but do not refuse the run —
   operator may have legit reasons (e.g. canary build).

4. Add a CI step to `.github/workflows/sandbox-images.yml` that diffs the
   Dockerfile-baked versions against the YAML `version:` fields and fails
   if any drift > minor version.

## Workaround (current Cycle 3 state)

* Source of truth for pinned versions is the Dockerfile, not the YAML.
* `docs/sandbox-images.md` §1.1 documents the version matrix for human
  review.
* The hardening contract test
  (`backend/tests/integration/sandbox/test_image_security_contract.py`)
  verifies the `argus.image.cycle="ARG-026"` label and the canonical
  base image pin (`kalilinux/kali-rolling:2026.1`) — those at least
  guarantee the image is built from a known good template.

No production impact in Cycle 3 because the operator running the sandbox
driver is the same person building the images (single-org deployment per
the §1 charter). Becomes a real issue in Cycle 5 when third-party tenants
start consuming the catalog.

## Out-of-scope follow-ups

* Catalog signing: the YAMLs are already Ed25519-signed, but the version
  string would need to be in the signature payload. Trivial change to
  `backend/src/sandbox/tool_registry.py::sign_tool_descriptor`.
* OCI image label parity: bake the per-tool versions into the image as
  individual `LABEL argus.tool.<name>.version="…"` labels. Lets Trivy /
  Grype map findings back to a specific tool YAML automatically.

## Verification commands

```powershell
# Confirm the gap (no `version:` field anywhere in the catalog).
Get-ChildItem backend/config/tools/*.yaml | ForEach-Object {
    if (-not (Select-String -Path $_.FullName -Pattern "^version:" -Quiet)) {
        Write-Output "$($_.Name): NO version field"
    }
}

# Confirm that the Dockerfile pins are visible (alternative source of truth).
Select-String -Path "sandbox/images/argus-kali-web/Dockerfile" -Pattern "@v[0-9]+\.[0-9]+"
```
