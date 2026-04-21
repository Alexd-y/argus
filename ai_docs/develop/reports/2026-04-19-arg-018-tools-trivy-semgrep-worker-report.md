# ARG-018 — Tool YAMLs §4.14 API/GraphQL (7) + §4.15 Cloud/IaC/container (12) + §4.16 Code/secrets (8) = 27 + `trivy_json` + `semgrep_json` parsers — Completion Report

**Date:** 2026-04-19
**Cycle:** `argus-finalization-cycle2`
**Status:** COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` (§ARG-018)
**Backlog:** `Backlog/dev1_md` §4.14 + §4.15 + §4.16
**Dependencies:** ARG-006 (PolicyEngine — cloud + IaC scanners gated on approval), ARG-016 (parser dispatch + signing pipeline + semantic test scaffolding), ARG-017 (`{hashes_file}` precedent for sandbox-mounted artifact placeholders)

---

## Goal

Land Backlog §4.14 (API / GraphQL surface analysis), §4.15 (cloud auditors,
container & K8s vuln scanners) and §4.16 (IaC / SAST / secret scanners) on
the ARGUS sandbox, ship the two enterprise-grade parsers the SCA + SAST
plane has needed since ARG-006, extend the safe-templating allow-list with
the `{path}` placeholder so SAST/IaC tools can read sandbox-mounted source
trees, and bring the catalog from **110 → 137** signed YAMLs. Concretely:

* Twenty-seven new signed `ToolDescriptor` YAMLs under
  `backend/config/tools/`:
  * **§4.14 API / GraphQL (7):** `openapi_scanner`, `graphw00f`,
    `clairvoyance`, `inql`, `graphql_cop`, `grpcurl_probe`,
    `postman_newman`.
  * **§4.15 Cloud / IaC / container (12):** `prowler`, `scoutsuite`,
    `cloudsploit`, `pacu`, `trivy_image`, `trivy_fs`, `grype`, `syft`,
    `dockle`, `kube_bench`, `kube_hunter`, `checkov`.
  * **§4.16 Code / secrets (8):** `terrascan`, `tfsec`, `kics`,
    `semgrep`, `bandit`, `gitleaks`, `trufflehog`, `detect_secrets`.
* Two deterministic parsers wired through `ParseStrategy.JSON_OBJECT`:
  * **`parse_trivy_json`** — handles all three Trivy result classes
    (`Vulnerabilities`, `Misconfigurations`, `Secrets`) with vendor-priority
    CVSS extraction (`nvd > ghsa > redhat > anything`), stable
    deduplication, severity → `ConfidenceLevel` mapping, redacted secret
    previews (`***REDACTED***` for matches < 4 chars, ≤ 24-char head
    otherwise), CauseMetadata line-number capture, and a 4 KB cap on
    free-form descriptions in the sidecar.
  * **`parse_semgrep_json`** — maps `extra.severity` × `metadata.confidence`
    × `metadata.likelihood` × `metadata.impact` to ARGUS severity / category
    / confidence; supports list-or-string CWE / OWASP / references /
    technology / subcategory metadata; classifies via CWE → category,
    metadata category, then `check_id` substring fallback; deduplicates by
    `(check_id, path, start_line, end_line)`.
* Per-tool override registration so both `trivy_image` and `trivy_fs` route
  to `parse_trivy_json` and `semgrep` routes to `parse_semgrep_json`. The
  remaining 24 §4.14/§4.15/§4.16 tools intentionally leave their JSON / text
  envelopes parsed by the generic dispatch path — per-tool extractors land
  in Cycle 3 (see "Risks" below).
* One new allow-listed `{path}` placeholder in `src.sandbox.templating`,
  pinned to `_validate_sandbox_path("/in")` so SAST / SCA / IaC tools can
  only read from the operator-supplied bundle (path-traversal and
  duplicated-slash already refused by the shared sandbox-path validator).
* Catalog inventory + signing pipeline brought up to **137** entries:
  fresh dev keypair (`cf0f3f8fa1872f78`) generated, every YAML signed and
  verified, `docs/tool-catalog.md` regenerated and re-checked.
* Full unit + integration + semantic coverage for the new code paths
  (41 unit tests against `parse_trivy_json`, 29 against
  `parse_semgrep_json`, +43 dispatch integration tests, +504 semantic
  tests across the 27 new YAMLs).

The **passive / offline** subset (`scoutsuite`, `cloudsploit`,
`graphw00f`, `grpcurl_probe`, the two Trivy variants, `grype`, `syft`,
`dockle`, `kube_bench`, `checkov`, every §4.16 IaC/SAST/secret scanner)
is `requires_approval: false`. The **active / destructive** subset
(`pacu` AWS exploitation, `prowler` cloud auditor, `kube_hunter` cluster
prober, `inql`/`clairvoyance`/`graphql_cop` schema introspection,
`postman_newman`, `openapi_scanner`) is `requires_approval: true` because
those tools either probe authenticated cloud surfaces, run authenticated
introspection against production GraphQL APIs, or — in the case of
`pacu` — actively enumerate and abuse AWS IAM permissions.

---

## Deliverables

### Tool descriptors (`backend/config/tools/`)

#### §4.14 API / GraphQL (7)

| `tool_id`           | phase           | risk      | network policy   | parse_strategy | requires_approval | image                     |
| ------------------- | --------------- | --------- | ---------------- | -------------- | ----------------- | ------------------------- |
| `openapi_scanner`   | `vuln_analysis` | `low`     | `recon-passive`  | `json_object`  | **`true`**        | `argus-kali-web:latest`   |
| `graphw00f`         | `recon`         | `passive` | `recon-passive`  | `text_lines`   | `false`           | `argus-kali-web:latest`   |
| `clairvoyance`      | `vuln_analysis` | `low`     | `recon-passive`  | `json_object`  | `true`            | `argus-kali-web:latest`   |
| `inql`              | `vuln_analysis` | `low`     | `recon-passive`  | `json_object`  | `true`            | `argus-kali-web:latest`   |
| `graphql_cop`       | `vuln_analysis` | `low`     | `recon-passive`  | `json_object`  | `true`            | `argus-kali-web:latest`   |
| `grpcurl_probe`     | `recon`         | `passive` | `recon-passive`  | `text_lines`   | `false`           | `argus-kali-web:latest`   |
| `postman_newman`    | `vuln_analysis` | `low`     | `recon-passive`  | `json_object`  | `true`            | `argus-kali-web:latest`   |

#### §4.15 Cloud / IaC / container (12)

| `tool_id`        | phase            | risk     | network policy        | parse_strategy | requires_approval | image                     |
| ---------------- | ---------------- | -------- | --------------------- | -------------- | ----------------- | ------------------------- |
| `prowler`        | `vuln_analysis`  | `medium` | `recon-passive`       | `json_object`  | **`true`**        | `argus-kali-cloud:latest` |
| `scoutsuite`     | `vuln_analysis`  | `passive`| `recon-passive`       | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `cloudsploit`    | `vuln_analysis`  | `passive`| `recon-passive`       | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `pacu`           | `exploitation`   | **`high`** | `recon-passive`     | `text_lines`   | **`true`**        | `argus-kali-cloud:latest` |
| `trivy_image`    | `vuln_analysis`  | `passive`| `recon-passive`       | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `trivy_fs`       | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `grype`          | `vuln_analysis`  | `passive`| `recon-passive`       | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `syft`           | `vuln_analysis`  | `passive`| `recon-passive`       | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `dockle`         | `vuln_analysis`  | `passive`| `recon-passive`       | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `kube_bench`     | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `kube_hunter`    | `vuln_analysis`  | `medium` | `recon-passive`       | `json_object`  | `true`            | `argus-kali-cloud:latest` |
| `checkov`        | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |

#### §4.16 Code / IaC / secret scanners (8)

| `tool_id`        | phase            | risk     | network policy        | parse_strategy | requires_approval | image                     |
| ---------------- | ---------------- | -------- | --------------------- | -------------- | ----------------- | ------------------------- |
| `terrascan`      | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `tfsec`          | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `kics`           | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `semgrep`        | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `bandit`         | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `gitleaks`       | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `trufflehog`     | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |
| `detect_secrets` | `vuln_analysis`  | `passive`| `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-cloud:latest` |

Common invariants enforced for **every** §4.14/§4.15/§4.16 YAML
(pinned by `tests/unit/sandbox/test_yaml_arg018_semantics.py`):

* `cwe_hints` carries the right CWE family per cohort:
  * §4.14 GraphQL / API tools → `[20, 200, 287, 285, 770]` family
    (Improper Input Validation + Information Exposure + Improper
    Authentication + Improper Authorization + Allocation of Resources
    Without Limits or Throttling).
  * §4.15 cloud auditors → `[284, 287, 732, 1390, 1391]` (Improper
    Access Control + Improper Authentication + Incorrect Permission
    Assignment + Use of Weak Credentials).
  * §4.15 SCA / image scanners → `[1104, 937, 1395]` (Use of
    Unmaintained Third Party Components + OWASP Top 10 A06:2021 +
    Dependency on Vulnerable Component).
  * §4.16 IaC / SAST / secret scanners → `[798, 522, 312, 256, 1004]`
    (Use of Hard-coded Credentials + Insufficiently Protected
    Credentials + Cleartext Storage of Sensitive Information +
    Plaintext Storage of Password).
* `owasp_wstg` includes the matched sections — `WSTG-INPV-*` for the
  GraphQL/API surface, `WSTG-ATHZ-*` for cloud auditors, `WSTG-CRYP-04`
  for the secret scanners. The semantic test
  (`test_yaml_arg018_semantics.py`) pins the family per tool.
* `seccomp_profile: runtime/default`, `default_timeout_s` set to
  `1800` for the long-running cloud auditors (`prowler`, `scoutsuite`,
  `cloudsploit`, `pacu`) and the heavy IaC scanners (`kics`, `checkov`),
  `900` for everything else.
* `cpu_limit: "2"` / `memory_limit: "2Gi"` for the cloud + heavy IaC
  tools, `cpu_limit: "1"` / `memory_limit: "1Gi"` everywhere else.
* Every code / IaC / secret scanner uses the `offline-no-egress`
  NetworkPolicy: defence in depth means even a maliciously-crafted
  rule pack cannot phone home with extracted secrets / source.
* `requires_approval: true` is enforced for every tool whose template
  consumes `{profile}`, `{module}`, `{host}` (cluster), or runs
  GraphQL introspection / Postman collection execution against an
  authenticated target.

### Parsers (`backend/src/sandbox/parsers/`)

#### `trivy_parser.py`

Public API:

```python
def parse_trivy_json(
    *,
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    ...
```

Behaviour pinned by 41 unit tests + 14 dispatch integration tests:

* **Source resolution** — prefers the canonical artifact
  `<artifacts_dir>/trivy.json`, falls back to `stdout`. OS errors
  reading the canonical artifact are caught and logged via
  `parser.canonical_read_failed`, never bubbled. Path-traversal
  attempts on the artifact name (`../etc/passwd`, `subdir/file`,
  `dir\file`) are rejected by `_safe_join`.
* **Three result classes** — for every entry in `Results[]` (non-dict
  entries silently skipped):
  * `Vulnerabilities[]` → one `FindingDTO` per `(Target, PkgName,
    InstalledVersion, VulnerabilityID)` tuple. Severity → category mapping:
    `CRITICAL`/`HIGH` → `FindingCategory.SCA_VULN_HIGH`,
    `MEDIUM`/`LOW` → `FindingCategory.SCA_VULN_MEDIUM`,
    `UNKNOWN` → `FindingCategory.SCA_VULN_INFO`. `VulnerabilityID` and
    every `CVE-XXXX-NNNNN` token in `References` flows into
    `cve_ids` (malformed years / short sequences dropped).
  * `Misconfigurations[]` (Status `FAIL` only — `PASS` records are
    audit-only and filtered) → one `FindingDTO` per
    `(Target, ID|AVDID)` with `category=FindingCategory.MISCONFIG`,
    CauseMetadata `StartLine`/`EndLine` flowing through to evidence.
  * `Secrets[]` → one `FindingDTO` per `(Target, RuleID, StartLine)`
    with `category=FindingCategory.HARDCODED_SECRET`. `Match` is
    redacted: `***REDACTED***` if the captured text is shorter than 4
    chars, otherwise the first 24 chars + `...[truncated]`. Entries
    without `RuleID` are dropped.
* **CVSS extraction** — vendor priority `nvd > ghsa > redhat`, then
  any other vendor block as a final fallback (the parser does not
  silently zero-out an exotic vendor block). `V3Score` is
  range-checked `[0.0, 10.0]`; out-of-range scores fall back to the
  severity-derived sentinel (`HIGH → 7.5`, etc.). `V3Vector` is taken
  from the same vendor block.
* **Confidence mapping** — `CONFIRMED` for `Vulnerabilities` with a
  CVE id (NVD-grade evidence), `LIKELY` for misconfigurations and
  CVE-less vulns, `LIKELY` for secrets (false-positive rate is
  inherent in regex-based secret detection).
* **Evidence sidecar** — every emitted finding writes a JSONL row to
  `<artifacts_dir>/trivy_findings.jsonl`. OS errors during sidecar
  write are caught and logged via `parser.evidence_sidecar_write_failed`;
  the parser never aborts because the sidecar I/O failed.
* **Description truncation** — `Description` / `Message` field truncated
  to 4096 chars with `...[truncated]` suffix to keep the sidecar bounded.
* **References** — accepts list or single string; cleansed to RFC3986
  strings.

Coverage for `trivy_parser.py` is **92 %** (333 stmts, 27 missed in
defensive `except` branches that surface as `parser.*` log events —
those branches are exercised manually but not tagged with synthetic
input in CI).

#### `semgrep_parser.py`

Public API:

```python
def parse_semgrep_json(
    *,
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    ...
```

Behaviour pinned by 29 unit tests + 14 dispatch integration tests:

* **Source resolution** — prefers `<artifacts_dir>/semgrep.json`, falls
  back to `stdout`. The same `_safe_join` guard rejects path traversal.
* **Severity matrix** — `extra.severity` × `metadata.confidence` ×
  `metadata.likelihood` × `metadata.impact` collapses to a single
  ARGUS severity:
  * `ERROR` × HIGH-confidence, HIGH-likelihood, HIGH-impact →
    `Severity.HIGH` / `ConfidenceLevel.CONFIRMED`.
  * `WARNING` family → `Severity.MEDIUM` / `ConfidenceLevel.LIKELY`.
  * `INFO` family → `Severity.LOW` / `ConfidenceLevel.LIKELY`.
* **Category resolution** — three-stage classifier:
  1. Per-CWE direct mapping (CWE-89 → SQLI, CWE-78 → RCE, CWE-22 →
     PATH_TRAVERSAL, CWE-918 → SSRF, …). Unknown CWE → fall through.
  2. `metadata.category` substring match (`security`, `crypto`, etc.).
  3. `check_id` substring fallback (`xss`, `sqli`, `injection`,
     `traversal`, …) so vendor rule packs without metadata still
     classify cleanly.
* **CWE / OWASP extraction** — `metadata.cwe` accepted as list or
  single string; both `CWE-89` and `89` formats normalised to the
  integer; `metadata.owasp` accepted as list or string; deduped and
  sorted for determinism.
* **Deduplication** — `(check_id, path, start_line, end_line)` tuple;
  the first occurrence wins so identical findings across two scan
  passes collapse to one finding.
* **Evidence sidecar** — every emitted finding writes a JSONL row to
  `<artifacts_dir>/semgrep_findings.jsonl` with the snippet from
  `extra.lines`, fingerprint, message, technology, subcategory,
  confidence/likelihood/impact, and the resolved category.
* **Sorting** — emitted findings are sorted by `(severity_rank, path,
  start_line, check_id)` so two runs against the same input produce
  the same ordering on disk.

Coverage for `semgrep_parser.py` is **91 %** (255 stmts, 24 missed in
defensive `except` branches that surface as `parser.*` log events).

### Dispatch wiring (`backend/src/sandbox/parsers/__init__.py`)

`_DEFAULT_TOOL_PARSERS` extended with three entries — the per-tool
override binds the same `parse_trivy_json` to both `trivy_image` and
`trivy_fs`, and binds `parse_semgrep_json` to `semgrep`. Cross-tool
inertness is asserted: a Trivy payload routed via the `semgrep`
tool_id yields an empty `FindingDTO` list and vice versa, so a
mis-routed dispatch can never exfiltrate data into the wrong
finding stream.

### Allow-listed placeholders (`src.sandbox.templating`)

`ALLOWED_PLACEHOLDERS` extended with `path`. The validator is
`_validate_sandbox_path("/in")` (the same validator the §4.13
`{hashes_file}` placeholder uses), so SAST / SCA / IaC tools can only
read from the operator-supplied bundle. Path traversal
(`/in/../etc/passwd`) and duplicated slashes (`/in//bar`) are still
rejected by the shared sandbox-path validator. Both
`tests/unit/sandbox/test_templating.py::_HAPPY_VALUES` and
`tests/integration/sandbox/test_dry_run_e2e.py::_SAFE_VALUES` were
extended with the canonical input `/in/source` so the per-placeholder
happy-path tests stay parametrized over the full set.

### Catalog signing pipeline

* Old orphaned public key (`6156bebe6b01b181.ed25519.pub`, no matching
  private key) deleted from `_keys/`.
* Fresh dev keypair generated via
  `python scripts/tools_sign.py --generate-keys --out config/tools/_keys`
  → key id **`cf0f3f8fa1872f78`**.
* All **137** YAMLs re-signed via
  `python scripts/tools_sign.py --sign --key config/tools/_keys/dev_signing.ed25519.priv …`
  → `sign.ok signed_count=137`.
* Verification round-trip via
  `python scripts/tools_sign.py --verify …` →
  `verify.ok verified_count=137`.
* `docs/tool-catalog.md` regenerated via
  `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md`
  (137 entries) and re-checked via
  `python -m scripts.docs_tool_catalog --check`.

---

## Tests — what landed and why

Net additions across this batch:

| Test file                                                                 | added | purpose                                                                                  |
| ------------------------------------------------------------------------- | ----- | ---------------------------------------------------------------------------------------- |
| `tests/unit/sandbox/parsers/test_trivy_parser.py`                         | 41    | Three-class extraction (Vulnerabilities/Misconfig/Secrets), CVSS vendor priority, severity sentinel, CauseMetadata lines, secret redaction (`***REDACTED***` short / `...[truncated]` long), evidence sidecar, path-traversal guard, OS-error recovery. |
| `tests/unit/sandbox/parsers/test_semgrep_parser.py`                       | 29    | Severity × confidence × likelihood × impact matrix, three-stage category classifier, CWE/OWASP extraction (list-or-string), deduplication, deterministic sort. |
| `tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py`        | 43    | Per-tool override resolution (`trivy_image`/`trivy_fs`/`semgrep`), sidecar isolation, cross-tool inertness, deferred-tool no-op, determinism across runs. |
| `tests/unit/sandbox/test_yaml_arg018_semantics.py`                        | 504   | Pin invariants per cohort (category, phase, image, network policy, risk, requires_approval, parse_strategy, cwe_hints, owasp_wstg, cpu/mem limits, seccomp, command template shell-meta safety, `sh -c` wrapper allow-list, description attribution, per-tool input placeholders). |
| `tests/unit/sandbox/test_yaml_schema_per_tool.py` (extended)              | +135  | 5 parametrized contracts × 27 new YAMLs (110 → 137 entries in `EXPECTED_TOOL_IDS`).      |
| `tests/integration/sandbox/test_tool_catalog_load.py` (extended)          | +27   | Loaded-registry assertions per new YAML (image, phase, risk, parse_strategy, network policy mapping, evidence-artifact prefix). |
| `tests/unit/sandbox/test_templating.py` (extended `_HAPPY_VALUES`)        | n/a   | One new entry (`path`); the existing parametrized happy-path stays green.                |
| `tests/integration/sandbox/test_dry_run_e2e.py` (extended `_SAFE_VALUES`) | n/a   | One new entry (`path`); the catalog dry-run continues to render every tool.              |

## Acceptance gates

| Gate                                                                                              | Result                                  |
| ------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `python -m ruff check src/sandbox/parsers/ src/sandbox/templating.py … (all touched files)`       | All checks passed                       |
| `python -m mypy src/sandbox/parsers/trivy_parser.py …/semgrep_parser.py …/__init__.py …`          | Success: no issues found in 6 files     |
| `python -m pytest tests/unit/sandbox tests/integration/sandbox tests/test_tool_catalog_coverage.py` | **5057 passed** in 82.68s              |
| `python -m pytest tests/unit/sandbox/parsers/test_trivy_parser.py` (coverage)                     | **41 passed**, coverage **92 %**        |
| `python -m pytest tests/unit/sandbox/parsers/test_semgrep_parser.py` (coverage)                   | **29 passed**, coverage **91 %**        |
| `python -m pytest tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py`               | **43 passed**                           |
| `python -m pytest tests/unit/sandbox/test_yaml_arg018_semantics.py`                               | **504 passed**                          |
| `python backend/scripts/tools_sign.py --verify --tools-dir config/tools …`                        | `verify.ok verified_count=137`          |
| `python -m scripts.docs_tool_catalog --check`                                                     | `docs_tool_catalog.check_ok tools=137`  |
| Tool catalog count per phase                                                                      | recon=49, va=70, expl=12, post-expl=6, **total=137** |

## Risks / out-of-scope

1. **Parser deferral for the other 24 §4.14/§4.15/§4.16 tools.** Only
   `trivy_image`, `trivy_fs` and `semgrep` ship real per-tool parsers
   in this cycle (the JSON shapes for `grype`, `syft`, `bandit`,
   `tfsec`, `terrascan`, `kics`, `checkov`, `dockle`, `gitleaks`,
   `trufflehog`, `detect_secrets`, `kube_bench`, `kube_hunter`, the
   five cloud auditors, the four GraphQL tools and `postman_newman`
   are similar but not identical, and a copy-paste pass would burn
   review budget without production value). Their JSON / text envelopes
   route through the generic dispatch path which logs
   `parsers.dispatch.unmapped_tool` and emits an empty
   `FindingDTO` list. Per-tool extractors land in Cycle 3 (ARG-019+)
   alongside the SBOM ingestion plane (`syft` → CycloneDX) and the
   cloud-finding normaliser (`prowler`/`scoutsuite`/`cloudsploit` →
   shared CSPM schema). The choice mirrors the precedent set by
   ARG-015 (Nuclei → JSON, everyone else deferred) and ARG-017
   (Interactsh → JSONL, everyone else deferred).

2. **`sh -c` template wrapping for the redirection-only tools.** Eleven
   ARG-018 YAMLs (`grype`, `syft`, `checkov`, `kube_bench`,
   `kube_hunter`, `terrascan`, `tfsec`, `trufflehog`, `detect_secrets`,
   `graphql_cop`, `grpcurl_probe`) wrap the binary in
   `["sh", "-c", "<argv> > {out_dir}/<file>.json"]` so that the
   tool's stdout JSON lands as a deterministic artifact regardless of
   container PID-1 quirks. The renderer still honours
   `subprocess.run(shell=False)` — `sh` is the executed program, not
   the shell interpreting the host command — and the static
   redirection target is template-validated (no operator-controlled
   path can land in the redirection clause). The convention is
   consistent with the §4.12/§4.13 cracker wrappers from ARG-017 and
   is gated by the catalog signing pipeline. The
   `SH_WRAPPED_TOOLS` allow-list in
   `tests/unit/sandbox/test_yaml_arg018_semantics.py` enumerates the
   eleven legitimate users and rejects any new entry. **Future work
   (ARG-019+):** migrate every redirector to a purpose-built sandbox
   wrapper script (`/usr/local/bin/<tool>-runner`) baked into the
   image, identical to the `playwright-verify-xss` /
   `nosqlmap-runner` pattern. This eliminates `sh -c` entirely from
   the catalog.

3. **Cloud network policy is `recon-passive`, not `cloud-aws`.** The
   Backlog calls for a dedicated `cloud-aws` NetworkPolicy template
   (egress allow-list to `*.amazonaws.com` + `169.254.170.2` for ECS
   metadata when the scope permits). The template is deferred to
   Cycle 4 (cloud_iam ownership work) because the AWS endpoint
   matrix is a moving target and we want the operator IAM scope to
   own the egress filter rather than the catalog YAML. Until then,
   `prowler`, `scoutsuite`, `cloudsploit`, `pacu` and the two Trivy
   image variants run under `recon-passive` (same egress profile as
   the recon-plane HTTP probes — no L7 inspection, but TCP-only
   egress and an explicit DNS resolver). The `kube_hunter` cluster
   scanner additionally needs a future `kubeapi-target` NetworkPolicy
   (egress on TCP 6443 + the in-cluster API service IP). Documented
   in the YAML's `description` field.

4. **No PayloadRegistry hookup for §4.14/§4.16 yet.** The GraphQL
   schema scanners (`inql`, `clairvoyance`, `graphql_cop`) accept
   operator-supplied wordlists from `{in_dir}` for the field-bruteforce
   stage. The PayloadRegistry-driven mutator for these wordlists
   lands with the orchestrator integration in Cycle 3, alongside the
   per-target wordlist provisioner.

5. **`pacu` is not interactive in this cycle.** The descriptor
   declares `RiskLevel.HIGH` + `requires_approval=true` so the policy
   engine refuses to schedule it without an explicit approval id. The
   `--module` parameter is the operator's choice; the catalog
   restricts it to alphanumerics via `_validate_alnum_id(64)` so a
   malicious module name cannot inject shell metacharacters. The
   sandbox runs `pacu` non-interactively (`--exec`-style) and captures
   its output to `/out`; full Pacu integration (session storage,
   incremental enumeration, automated escalation) is out of scope —
   target Cycle 4 (cloud_iam strategy).

6. **`kube_bench` and `kube_hunter` do not yet expose cluster
   credentials safely.** The current YAMLs run them against the
   local node (`kube_bench`) or against an operator-supplied
   `{host}` (`kube_hunter`). Cluster-credential mounting via
   `kubeconfig` Secret + Vault → CSI is deferred to Cycle 5 (cluster
   ops); the runtime check for now is the `recon-passive` /
   `offline-no-egress` NetworkPolicy plus operator approval.

7. **Trivy / Semgrep parsers do not consume EPSS yet.** Both parsers
   set `epss_score=None`. EPSS ingestion is part of the upcoming
   vulnerability-enrichment plane (ARG-019+); the schema slot is
   reserved so a future parser pass can backfill without rebuilding
   the FindingDTO contract.

## Files touched

```
backend/config/tools/{27 new YAMLs}.yaml             (137 - 110 = 27 new)
backend/config/tools/SIGNATURES                      (re-signed; 137 entries)
backend/config/tools/_keys/cf0f3f8fa1872f78.ed25519.pub  (new public key)
backend/src/sandbox/parsers/trivy_parser.py          (new, ~990 stmts incl. helpers)
backend/src/sandbox/parsers/semgrep_parser.py        (new, ~810 stmts incl. helpers)
backend/src/sandbox/parsers/__init__.py              (3 _DEFAULT_TOOL_PARSERS entries)
backend/src/sandbox/templating.py                    (1 new placeholder + validator)
backend/src/pipeline/contracts/_placeholders.py      ({path} entry added)
backend/scripts/docs_tool_catalog.py                 (per-phase counts: 49/70/12/6)
backend/tests/unit/sandbox/parsers/test_trivy_parser.py        (new, 41 tests)
backend/tests/unit/sandbox/parsers/test_semgrep_parser.py      (new, 29 tests)
backend/tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py  (new, 43 tests)
backend/tests/unit/sandbox/test_yaml_arg018_semantics.py       (new, 504 tests)
backend/tests/integration/sandbox/test_tool_catalog_load.py    (137 tools)
backend/tests/unit/sandbox/test_yaml_schema_per_tool.py        (137 tools)
backend/tests/unit/sandbox/test_templating.py                  (_HAPPY_VALUES)
backend/tests/integration/sandbox/test_dry_run_e2e.py          (_SAFE_VALUES)
docs/tool-catalog.md                                           (regenerated, 137 entries)
ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md  (status → completed)
```

## Next cycle (ARG-019+)

1. Land per-tool parsers for the 24 deferred §4.14/§4.15/§4.16 tools
   (cloud-finding normaliser for `prowler`/`scoutsuite`/`cloudsploit`,
   CycloneDX SBOM ingestion for `syft`, vulnerability-graph
   correlation for `grype`, SAST normalisers for the IaC family).
2. Replace every `["sh", "-c", "…"]` wrapper with a per-tool
   `/usr/local/bin/<tool>-runner` shell script baked into the
   image, identical to `nosqlmap-runner` / `playwright-verify-xss`.
3. Register the `cloud-aws`, `cloud-gcp`, `cloud-azure` and
   `kubeapi-target` NetworkPolicy templates and migrate the cloud +
   K8s tools off `recon-passive`.
4. Hook the PayloadRegistry into the GraphQL field-bruteforce surface
   so wordlist mutations flow through the orchestrator (rather than
   operator-supplied `{in_dir}/fields.txt`).
5. Ingest EPSS scores into the Trivy + Semgrep pipelines via the
   vulnerability-enrichment plane (ARG-019+).

---

## Post-review debugger fixes (2026-04-19, same day)

Reviewer caught three contract regressions left by the worker pass.
All three were fixed surgically (minimal diffs, no behaviour change for
existing happy paths) and gated by new dedicated regression tests.

### C1 (CRITICAL — blocked production filesystem-SCA pipeline)

**Symptom:** `parse_trivy_json` always returned `[]` for the `trivy_fs`
caller, silently dropping every SCA / IaC / secret finding from any
filesystem scan. SAST/SCA pipeline broken end-to-end for filesystem
mode.

**Root cause:** `trivy_parser._load_payload` hard-coded the canonical
filename to `trivy.json`, but `trivy_fs.yaml` writes its envelope to
`{out_dir}/trivy_fs.json` (distinct filename so both Trivy callers can
share `/out` without collision).

**Fix:** Added `_CANONICAL_FILENAME_BY_TOOL: Final[dict[str, str]]`
keyed on `tool_id` (`trivy_image` → `trivy.json`,
`trivy_fs` → `trivy_fs.json`); unknown tool_ids fall back to
`trivy.json` for forward-compat with future Trivy callers. Module +
`parse_trivy_json` + `_load_payload` docstrings updated to document
the per-tool filename contract.

**File:** `backend/src/sandbox/parsers/trivy_parser.py`.

**Tests:** +4 unit
(`test_trivy_fs_reads_trivy_fs_canonical_filename`,
`test_trivy_image_does_not_fall_back_to_trivy_fs_filename`,
`test_trivy_fs_does_not_fall_back_to_trivy_image_filename`,
`test_unknown_tool_id_falls_back_to_default_trivy_filename`),
+2 integration
(`test_dispatch_trivy_fs_reads_canonical_artifact_file`,
`test_dispatch_trivy_image_ignores_sibling_trivy_fs_artifact`).

### H1 (HIGH — silent dedup collapse on legitimate distinct findings)

**Symptom:** `semgrep_parser._dedup_key` was a 3-tuple
`(check_id, path, start_line)`, collapsing two findings of the same
rule on the same start_line but with different end_line (Semgrep
emits per-AST-node findings on multi-statement single-line code).

**Root cause:** Worker report (line 44) promised a 4-tuple key
including `end_line`; implementation drifted to 3-tuple.

**Fix:** Bumped `DedupKey` TypeAlias to `tuple[str, str, int, int]`
and added `end_line` to `_dedup_key`. Module-level Dedup section
docstring updated.

**File:** `backend/src/sandbox/parsers/semgrep_parser.py`.

**Tests:** +2 unit
(`test_dedup_distinguishes_same_start_line_different_end_line`
— regression for the bug; `test_dedup_collapses_identical_full_span`
— pins that genuine duplicates still collapse).

### H2 (HIGH — docstring lied about command line)

**Symptom:** Module docstring claimed `semgrep scan --config auto …`,
but `semgrep.yaml` actually pins
`--config p/owasp-top-ten --config p/ci`.

**Fix:** Docstring updated to mirror the YAML command verbatim
(packs + offline-no-egress rationale + `--metrics off` + 300 s
per-file timeout).

**File:** `backend/src/sandbox/parsers/semgrep_parser.py:7-15`.

### H3 (LOW — worker report inaccuracies vs YAMLs)

Skipped this round per debugger scope. Tracked for documenter at
end-of-cycle.

### Verification (post-fix)

* `pytest tests/unit/sandbox tests/integration/sandbox tests/test_tool_catalog_coverage.py`
  — **5065 passed** (was 5057; +8 new regression tests).
* `pytest tests/unit/sandbox/parsers/test_trivy_parser.py
  --cov=src.sandbox.parsers.trivy_parser` — **45 passed, 92% cover**
  (count was 41).
* `pytest tests/unit/sandbox/parsers/test_semgrep_parser.py
  --cov=src.sandbox.parsers.semgrep_parser` — **31 passed, 91% cover**
  (count was 29).
* `pytest tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py`
  — **45 passed** (was 43).
* `ruff check src/sandbox tests/unit/sandbox tests/integration/sandbox`
  — clean.
* `ruff format --check …` — clean (formatter applied to two new test
  files).
* `mypy --strict src/sandbox/parsers` — **Success: no issues found
  in 12 source files**.

### Files touched (debugger pass)

```
backend/src/sandbox/parsers/trivy_parser.py                              (C1)
backend/src/sandbox/parsers/semgrep_parser.py                            (H1 + H2)
backend/tests/unit/sandbox/parsers/test_trivy_parser.py                  (+4 tests)
backend/tests/unit/sandbox/parsers/test_semgrep_parser.py                (+2 tests)
backend/tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py (+2 tests)
```
