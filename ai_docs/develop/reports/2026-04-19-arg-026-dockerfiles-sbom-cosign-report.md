# ARG-026 — Multi-stage Dockerfiles + SBOM + Cosign signing skeleton

**Worker:** Cycle 3 ARG-026 worker (Cursor / Claude Opus 4.7)
**Plan reference:** `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` lines 312-355
**Workflow:** Worker → Security-auditor → Test-runner → Reviewer (this report covers the worker pass)
**Date:** 2026-04-19
**Status:** ✅ Completed

---

## 1. Executive summary

Replaced the four Cycle 2 header-only stub Dockerfiles
(`sandbox/images/argus-kali-{web,cloud,browser,full}/Dockerfile`) with
production-ready multi-stage builds satisfying the ARG-026 hardening
contract:

* **Multi-stage:** every Dockerfile is `FROM kalilinux/kali-rolling:2026.1
  AS builder` + a slim runtime stage.
* **Pinned versions:** 16 Go + 14 Python + 2 npm + 1 ruby-gem on `web`;
  7 Go + 10 Python + 3 release tarballs + 1 npm on `cloud`; 2 Python + 2
  npm on `browser`; superset (16 Go + 8 Python) plus apt rolling on
  `full`. Per-version source matrix in `docs/sandbox-images.md` §1.1.
* **`USER 65532`** in every final stage with matching `useradd
  --uid 65532` + `groupadd --gid 65532` (k8s `runAsUser` contract).
* **`HEALTHCHECK`** wired to `/usr/local/bin/healthcheck.sh` (shared
  helper script, stub for Cycle 3, replaced by a real readiness probe in
  Cycle 4).
* **SBOM** generated at build time at the canonical path
  `/usr/share/doc/sbom.cdx.json` and surfaced via the
  `LABEL argus.sbom.path=...`. `cloud` and `full` use real `syft` (baked
  into the image); `web` and `browser` fall back to a `dpkg-query`
  CycloneDX 1.5 envelope built by the shared helper.
* **No SUID introduction:** zero `chmod +s` / `chmod 4755` patterns; the
  browser image explicitly removes Chromium's setuid sandbox.
* **OCI + ARGUS labels:** `org.opencontainers.image.{title,description,
  source,version,licenses}` + `argus.image.{profile,cycle}` + `argus.
  sbom.path` on every image.
* **Cosign skeleton:** dry-run by default; real signing when
  `COSIGN_KEY` is set; SBOM attestation as CycloneDX predicate.

The full hardening contract is enforced statically by **65 assertions**
in `backend/tests/integration/sandbox/test_image_security_contract.py`,
running in <1 s without a Docker daemon.

---

## 2. Files created / modified (full paths)

| Path | Status | LoC | Purpose |
|------|--------|-----|---------|
| `sandbox/images/argus-kali-web/Dockerfile` | modified (stub → real) | 240 | Web/HTTP/VA tooling image |
| `sandbox/images/argus-kali-cloud/Dockerfile` | modified (stub → real) | 175 | Cloud / IaC / SAST / SCA tooling image |
| `sandbox/images/argus-kali-browser/Dockerfile` | modified (stub → real) | 172 | Playwright + Chromium browser image |
| `sandbox/images/argus-kali-full/Dockerfile` | modified (stub → real) | 194 | Monolithic superset (safety net) |
| `sandbox/images/_shared/healthcheck.sh` | new | 24 | Shared HEALTHCHECK script |
| `sandbox/images/_shared/generate_sbom.sh` | new | 104 | CycloneDX 1.5 JSON SBOM generator |
| `infra/scripts/build_images.sh` | new | 164 | Local + CI build helper |
| `infra/scripts/sign_images.sh` | new | 223 | Cosign signing pipeline (dry-run by default) |
| `.github/workflows/sandbox-images.yml` | new | 209 | CI: hardening contract → build + SBOM → Cosign |
| `backend/tests/integration/sandbox/test_image_security_contract.py` | new | 509 | Static-analysis hardening contract (65 assertions) |
| `docs/sandbox-images.md` | new | 285 | Image profile matrix, hardening, SBOM, Cosign recipes |
| `ai_docs/develop/issues/ISS-cycle3-tool-yaml-version-field.md` | new | 110 | Follow-up: catalog YAMLs lack `version:` field |
| `CHANGELOG.md` | modified | +35 | `[Unreleased] / Added (ARG-026)` entry |
| `.cursor/workspace/active/orch-2026-04-19-argus-cycle3/tasks.json` | modified | +43 | ARG-026 → completed + deliverables + metrics |
| `.cursor/workspace/active/orch-2026-04-19-argus-cycle3/progress.json` | modified | +2 | tasksCompleted: 0 → 4 (catch-up + ARG-026) |

**Total:** 4 Dockerfiles (modified), 2 shared helpers (new), 2 build/sign
scripts (new), 1 CI workflow (new), 1 hardening test (new), 1 doc (new),
1 issue file (new), 3 metadata updates.

**Net new lines:** ~2200 (excluding metadata).

---

## 3. Acceptance criteria checklist (vs. plan §3 ARG-026)

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | `argus-kali-web` Dockerfile multi-stage, pinned 9 §4.4 tools, USER 65532, healthcheck | ✅ | `sandbox/images/argus-kali-web/Dockerfile` lines 33 (builder) + 130 (runtime) + 229 (USER) + 234 (HEALTHCHECK) + 105-120 (Go pin block) + 83-100 (PyPI pin block); also covers §4.5–§4.14 |
| 2 | `argus-kali-cloud` Dockerfile same for §4.15+§4.16 (prowler, trivy, syft, semgrep, ...) | ✅ | `sandbox/images/argus-kali-cloud/Dockerfile` lines 33 + 107 + 168 (USER) + 171 (HEALTHCHECK) + 56-66 (PyPI) + 74-80 (Go) + 87-98 (release tarballs) |
| 3 | `argus-kali-browser` Playwright + Chromium, USER 65532, no SUID | ✅ | `sandbox/images/argus-kali-browser/Dockerfile` lines 76 + 165 (USER) + 168 (HEALTHCHECK) + 62-64 (playwright) + 99-129 (Chromium + SUID-removal RUN line 129) |
| 4 | `argus-kali-full` superset (apt-get without strict pinning OK), USER 65532 + healthcheck mandatory | ✅ | `sandbox/images/argus-kali-full/Dockerfile` lines 90 + 187 (USER) + 190 (HEALTHCHECK) + 107-158 (apt block, relaxed by spec) |
| 5 | All 4 images pass `docker build` (CI smoke) | ⏸ Deferred (CI) | No Docker daemon in worker env; CI workflow `.github/workflows/sandbox-images.yml` exercises real `docker build` via the `build-images` matrix on every PR. Worker explicitly **skipped** the local `docker build -f ... -t argus-kali-web:test ...` step per the task brief's "skip if docker daemon not available — note in report" guidance. |
| 6 | SBOM generated at build (`syft <image> -o cyclonedx-json` written, `LABEL argus.sbom.path=...` set) | ✅ | All 4 Dockerfiles RUN `/usr/local/bin/generate_sbom.sh /usr/share/doc/sbom.cdx.json` (lines 224, 165, 162, 184). Wrapper detects syft (cloud + full ship it) or falls back to dpkg-query envelope. Label set in every LABEL block. |
| 7 | `infra/scripts/sign_images.sh` Cosign skeleton (dry-run default; real if `COSIGN_KEY` set) | ✅ | `infra/scripts/sign_images.sh` line 87-90 (`DRY_RUN=1; if COSIGN_KEY ... DRY_RUN=0`); dry-run prints commands + sets `SIGNATURES_EMITTED+=("$TAG_FULL (dry-run)")`; real path runs `cosign sign --tlog-upload=false --recursive` + `cosign attest --predicate <SBOM> --type cyclonedx`. |
| 8 | Hardening contract test `tests/integration/sandbox/test_image_security_contract.py`: USER 65532, no SUID, SBOM presence, OCI+ARGUS labels | ✅ | 65 assertions across 8 test classes — `TestStructure`, `TestUserDirective`, `TestHealthcheck`, `TestLabels`, `TestSbomGeneration`, `TestNoSuidIntroduction`, `TestSharedHelpers`, `TestProfileSpecificContracts`, `TestBaseImagePin`. Run output: **65 passed in 0.98 s** (`pytest -q`). |
| 9 | CI pipeline `.github/workflows/sandbox-images.yml` — build + SBOM + Cosign on push to main | ✅ | 4 jobs: `hardening-contract`, `build-images` (matrix [web,cloud,browser,full]), `sign-images` (push to main), `sign-dry-run` (PR). SBOM extracted via `docker run --entrypoint cat` and validated inline with a Python CycloneDX schema check. |
| 10 | Documentation `docs/sandbox-images.md` — pinned versions per image + SBOM regen command | ✅ | §1.1 per-image pinned-version table (4 sub-tables, 70 rows total), §3 SBOM regen recipe (in-image extraction, forced regeneration, CI validation), §4 Cosign signing recipe, §2 16-row hardening-contract reference table. |

**Result: 9 / 10 acceptance criteria met; 1 deferred (CI smoke build) per
brief's explicit out-of-scope clause.**

---

## 4. Hardening contract assertions (65 cases, all PASS)

| Test class | Cases | Profiles | Asserts |
|------------|-------|----------|---------|
| `TestStructure` | 8 | 4 × 2 (file exists, multi-stage) | File present + ≥1500 B; ≥1 builder stage + ≥1 final non-builder stage; final stage alias is None |
| `TestUserDirective` | 8 | 4 × 2 | `USER 65532` in final stage; `useradd --uid 65532` + `groupadd --gid 65532` somewhere in the file |
| `TestHealthcheck` | 8 | 4 × 2 | `HEALTHCHECK` directive in final stage; invokes `/usr/local/bin/healthcheck.sh` |
| `TestLabels` | 20 | 4 × 5 | OCI labels (title/description/source); ARGUS labels (profile/cycle); profile label matches dir name; cycle == "ARG-026"; sbom.path == "/usr/share/doc/sbom.cdx.json" |
| `TestSbomGeneration` | 4 | 4 × 1 | `generate_sbom.sh` invoked at build + canonical SBOM path referenced |
| `TestNoSuidIntroduction` | 4 | 4 × 1 | No `chmod +s`, `u+s`, `g+s`, `ug+s`, `a+s`, octal `4xxx` patterns |
| `TestSharedHelpers` | 6 | shared (2) + 4 × 1 | Both `_shared/*.sh` exist with shebangs + content markers; every Dockerfile COPYs them |
| `TestProfileSpecificContracts` | 3 | per-profile | Browser: chrome-sandbox referenced for removal; Cloud: ships syft; Full: contains nuclei + trivy + chromium |
| `TestBaseImagePin` | 4 | 4 × 1 | Every stage's base is `kalilinux/kali-rolling:<pin>`, never `:latest` |
| **Total** | **65** | — | **65 / 65 PASS** |

Output of the focused run:

```text
.................................................................        [100%]
65 passed in 0.98s
```

---

## 5. Verification command results

All commands run from `backend/` on Windows / PowerShell:

### 5.1 Hardening contract (focused)

```powershell
python -m pytest tests/integration/sandbox/test_image_security_contract.py -q --tb=short
```

Output (last 4 lines):

```text
.................................................................        [100%]
65 passed in 0.98s
```

### 5.2 Sandbox integration regression (excluding the new file)

```powershell
python -m pytest tests/integration/sandbox -q --tb=short --ignore=tests/integration/sandbox/test_image_security_contract.py
```

Output (last line):

```text
1407 passed in 70.43s (0:01:10)
```

### 5.3 Lint / format checks on the new test file

```powershell
python -m ruff check tests/integration/sandbox/test_image_security_contract.py
python -m ruff format --check tests/integration/sandbox/test_image_security_contract.py
```

Output:

```text
All checks passed!
1 file already formatted
```

### 5.4 `docker build` smoke (skipped — no Docker daemon)

Per the task brief's "Optional (skip if docker daemon not available —
note in report)" clause, the `docker build -f
sandbox/images/argus-kali-web/Dockerfile -t argus-kali-web:test sandbox/`
step was **not** run locally. The same command lives in
`.github/workflows/sandbox-images.yml` job `build-images` (matrix over
`[web, cloud, browser, full]`) and will execute against an Ubuntu
runner on every PR + push to main.

---

## 6. Pre-existing issues encountered (out-of-scope)

### 6.1 ISS-cycle3-tool-yaml-version-field — catalog YAMLs lack `version:`

The task brief said "Pinned versions live in those YAMLs (`version`
field). Use them as the source of truth." Spot-check across all four
profiles confirmed that `backend/config/tools/*.yaml` (157 files) does
**not** carry a `version:` field today, and `ToolDescriptor` in
`backend/src/sandbox/tool_registry.py` does not expose one either.

The pragmatic fix: pinned versions live exclusively in the Dockerfiles
+ documented in `docs/sandbox-images.md` §1.1 for human review. Cycle 4
follow-up captured at `ai_docs/develop/issues/ISS-cycle3-tool-yaml-
version-field.md` to backfill the field, expose it via Pydantic, and add
a sandbox-driver mismatch warning.

### 6.2 Two extra image profiles in the catalog (`argus-kali-recon`, `argus-kali-binary`)

The catalog's per-tool YAMLs declare 6 image profiles total: the 4
covered by ARG-026 (`web`, `cloud`, `browser`, `full`) plus
`argus-kali-recon` (29 tools, mostly §4.1–§4.3 enumeration / passive
recon) and `argus-kali-binary` (5 tools, §4.18 binary / mobile). These
are pre-existing stubs (header-only Dockerfiles in `sandbox/images/`
that ARG-026 did not touch — the brief explicitly enumerated the four
images to build).

Resolver fallback rule (`backend/src/sandbox/image_resolver.py`) routes
unknown profiles to `argus-kali-full`, so this is not a runtime
regression. Cycle 5 will populate the two missing slim images. Captured
in `docs/sandbox-images.md` §1 ("Adding a new profile") + §7 ("Known
follow-ups").

### 6.3 Test environment: `pytest --collect-only` against the full suite

When verifying that the new test file does not regress collection time
across the broader sandbox suite, `pytest tests/integration/sandbox -q
--collect-only` reported **1473 items collected (was 1408)** — the +65
delta exactly matches the new test class count. No collection-time
errors. Compatible with ARG-028's marker discipline (the new file lives
under `tests/integration/sandbox/`, which is on the offline allowlist
per `backend/tests/conftest.py::pytest_collection_modifyitems`).

---

## 7. DoD checklist (plan §3 ARG-026)

* [x] 4 Dockerfiles converted from stubs → multi-stage production builds.
* [x] Each ships pinned versions for the §4.4–§4.19 tools assigned to its
      profile (per-version table in `docs/sandbox-images.md` §1.1).
* [x] Each runs `USER 65532` in the final stage with matching `useradd
      --uid 65532` + `groupadd --gid 65532` on the same OS user.
* [x] Each ships a `HEALTHCHECK` invoking `/usr/local/bin/healthcheck.sh`.
* [x] Each bakes a CycloneDX 1.5 JSON SBOM at
      `/usr/share/doc/sbom.cdx.json` (syft when present, dpkg-query
      fallback otherwise) and exposes the path via `LABEL
      argus.sbom.path=...`.
* [x] Each ships the required OCI labels
      (`org.opencontainers.image.{title,description,source,version,
      licenses}`) and ARGUS labels (`argus.image.{profile,cycle}`).
* [x] No `chmod +s` / `chmod 4xxx` patterns anywhere in any Dockerfile;
      browser image explicitly removes Chromium's SUID sandbox.
* [x] Shared helpers (`_shared/healthcheck.sh`, `_shared/generate_sbom.
      sh`) exist and are COPY'd into every image.
* [x] `infra/scripts/build_images.sh` builds one or all profiles with a
      flag, validates docker presence, surfaces per-profile failures.
* [x] `infra/scripts/sign_images.sh` defaults to dry-run, uses real
      Cosign when `COSIGN_KEY` is set, attests the SBOM as CycloneDX
      predicate, emits a JSON bundle of signed images.
* [x] `.github/workflows/sandbox-images.yml` runs hardening contract +
      matrix build + SBOM extract + validate + Trivy informational scan +
      Cosign sign (push to main) / dry-run (PR).
* [x] `backend/tests/integration/sandbox/test_image_security_contract.
      py` enforces all 16 hardening invariants statically (65
      assertions, no Docker daemon).
* [x] `docs/sandbox-images.md` documents image profiles, pinned versions,
      hardening contract, SBOM regen recipe, Cosign signing recipe,
      "adding a new profile" procedure.
* [x] `ai_docs/develop/issues/ISS-cycle3-tool-yaml-version-field.md`
      captures the only follow-up that arose during implementation.
* [x] `CHANGELOG.md` `[Unreleased]` block updated with the full
      `Added (ARG-026)` + `Metrics (ARG-026)` sections.
* [x] `.cursor/workspace/active/orch-2026-04-19-argus-cycle3/tasks.
      json` ARG-026 entry updated to `completed` with `completedAt`,
      `completionReport`, `deliverables`, `metrics`,
      `outOfScopeFollowUps` keys per the orchestration schema.

---

## 8. Hand-off recommendations

* **Security-auditor (next workflow step):** suggest auditing
  - `sandbox/images/argus-kali-browser/Dockerfile` line 129 — the
    `rm -f /usr/lib/chromium/chrome-sandbox` is the load-bearing line for
    the no-SUID contract. Verify the path matches the apt package
    contents on Kali rolling 2026.1 (the package has shipped this binary
    at this exact path since at least 2024.x).
  - `infra/scripts/sign_images.sh` — confirm the `--tlog-upload=false`
    flag is acceptable for the Cycle 3 skeleton (Cycle 5 will add Rekor
    + Fulcio).
  - The `sign-images` job's secret-handling — ensure the
    `COSIGN_PRIVATE_KEY` + `COSIGN_PASSWORD` secrets are properly scoped
    in the GitHub repo settings before the workflow runs against `main`.

* **Test-runner:** the worker has already verified the focused suite
  (65/65) and the broader sandbox regression (1407/1407). Suggest the
  test-runner additionally run:
  - `python -m pytest tests/integration/sandbox -q --tb=short` (full
    1472-item run, ~70 s) — validates the new file does not interact
    with the existing suite.
  - A `bash -n` syntax check on the three new shell scripts:
    `bash -n sandbox/images/_shared/healthcheck.sh sandbox/images/_shared/
    generate_sbom.sh infra/scripts/build_images.sh infra/scripts/
    sign_images.sh`.

* **Reviewer:** focus areas
  - The `_strip_comments_and_continuations` parser in
    `test_image_security_contract.py` — bespoke and load-bearing for the
    65 assertions. Suggest a unit test for the parser itself in Cycle 4
    once we know nothing else needs to use it.
  - The pinning strategy split (slim images strict, full image relaxed)
    — confirm this matches the §16.16 deployment intent.

* **Cycle 4 carry-over:**
  - Backfill `version:` field in tool YAMLs (ISS-cycle3-tool-yaml-
    version-field).
  - Replace the stub `healthcheck.sh` with a real readiness probe tied
    to the supervisor sidecar.
  - Populate `argus-kali-recon` + `argus-kali-binary` slim images.

* **Cycle 5 carry-over:**
  - Real Cosign keys + Rekor + Fulcio (drop `--tlog-upload=false`).
  - Helm chart publishing the SBOM as a Kubernetes ConfigMap.
  - Trivy / Grype gating with a CVSS threshold (currently informational
    only via `continue-on-error: true`).
