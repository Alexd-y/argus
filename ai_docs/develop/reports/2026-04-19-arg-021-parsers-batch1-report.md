# ARG-021 — Per-tool parsers batch 1 (JSON_OBJECT IaC/SAST/Cloud) — Completion Report

- **Cycle:** 3 (Finalisation cycle 3 / `2026-04-19-argus-finalization-cycle3.md`).
- **Backlog reference:** §4.15 (Cloud / IaC / container) + §4.16 (Code / secrets) + §4.18 (Mobile static) + §11 (Evidence pipeline) + §19.1 (Coverage).
- **Owner:** worker (Cycle 3 batch).
- **Completed:** 2026-04-19.
- **Status:** Completed — all 10 tools wired, all acceptance criteria met, no regressions in adjacent dispatch suites.

---

## 1. Summary

ARG-021 closes the highest-impact heartbeat gap in the cycle-2 catalog: the
ten flagship cloud / IaC / SAST / secret / mobile / SCA tools that
already shipped YAML descriptors but routed to the `ARGUS-HEARTBEAT`
fallback because no per-tool parser was wired into
`src.sandbox.parsers._DEFAULT_TOOL_PARSERS`.

After ARG-021 the per-tool dispatch table grows from **33 → 43**
mapped parsers; the heartbeat fallback drops from **124 → 114**
descriptors. Every new parser is a pure
`(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]`
function, follows the `trivy_parser` / `semgrep_parser` template, and
emits a tool-tagged JSONL evidence sidecar so multiple tools can run in
the same `/out` directory without overwriting each other.

The single most security-critical control — gitleaks raw-secret
redaction — is enforced by a dedicated integration test
(`test_gitleaks_redacts_secret_in_sidecar`) that fails CI if any byte of
the upstream `Secret` field reaches the sidecar.

---

## 2. Headline metrics

| Metric                                                | Before        | After         | Δ            |
| ----------------------------------------------------- | ------------- | ------------- | ------------ |
| Mapped per-tool parsers                               | 33            | **43**        | **+10 (+30 %)** |
| Heartbeat fallback descriptors                        | 124           | **114**       | **-10**          |
| Binary-blob descriptors                               | 0             | 0             | 0            |
| Catalog total descriptors                             | 157           | 157           | 0            |
| New parser modules                                    | —             | 10            | +10          |
| New unit tests (parser suites)                        | —             | 144           | +144         |
| New integration tests (`test_arg021_dispatch.py`)     | —             | 35            | +35          |
| Sandbox + catalog test surface (`tests/unit + tests/integration/sandbox + tests/test_tool_catalog_coverage.py`) | 7905          | **8049**      | +144         |
| `mypy src/sandbox/parsers`                            | clean         | clean         | —            |
| `ruff check src/sandbox/parsers`                      | clean         | clean         | —            |
| Raw secret bytes leaked through `gitleaks` sidecar    | n/a           | **0**         | enforced     |

The 144-test delta exactly matches the +10-parser × ≥10-cases-each
acceptance bar; the 35 integration cases cover the dispatch /
isolation / determinism / cross-routing / redaction guardrails.

---

## 3. Tools wired (10)

Every tool is registered for `ParseStrategy.JSON_OBJECT` in
`src.sandbox.parsers._DEFAULT_TOOL_PARSERS`:

| `tool_id`     | Family                          | Source shape                              | FindingCategory default                     | Special handling                                                  |
| ------------- | ------------------------------- | ----------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------- |
| `bandit`      | Python SAST                     | `results[]` with `issue_severity` + `issue_cwe.id` | derived from CWE / `test_id` prefix (B1xx/B6xx → RCE etc.) | Severity ladder maps Bandit `HIGH/MEDIUM/LOW` → ARGUS confidence ladder |
| `gitleaks`    | Secret scanner                  | top-level JSON array of leaks             | `SECRET_LEAK` (CWE-798)                     | **`Match` / `Secret` redacted** via `_base.redact_secret`; severity from rule keywords (aws/private → critical) |
| `kube_bench`  | Kubernetes CIS benchmark        | `Controls[].tests[].results[]`            | `MISCONFIG`                                  | Drops `PASS` / `INFO`; emits `FAIL` / `WARN` only; dedup includes `node_type` |
| `checkov`     | Multi-IaC (TF/CFN/K8s/Helm/Docker) | single-runner OR multi-runner envelope | `MISCONFIG` (`SECRET_LEAK` for `CKV_SECRET_*`) | Multi-runner envelope flattened transparently                     |
| `kics`        | Multi-IaC (Checkmarx)           | `queries[].files[]`                       | `MISCONFIG` (`SECRET_LEAK` for query-name keywords secret/password/credential) | CWE extracted from `cwe` field; severity ladder includes `TRACE` |
| `terrascan`   | Tenable IaC                     | `results.violations[]`                    | `MISCONFIG` (`SECRET_LEAK` for category `Secret*`/`Credentials`) | Confidence anchored by severity                                    |
| `tfsec`       | Aqua Terraform                  | `results[]` with `location.{filename,start_line}` | `MISCONFIG`                          | `CRITICAL` is first-class severity                                  |
| `dockle`      | CIS Docker benchmark            | `details[].alerts[]`                      | `MISCONFIG`                                  | Each alert is a separate finding; dedup by `(code, alert)`         |
| `mobsf_api`   | MoBSF mobile API report         | deeply-nested + version-variable envelope | `MISCONFIG` / `SECRET_LEAK` per section     | **Defensive walk** across `code_analysis` / `android_api` / `binary_analysis` / `manifest_analysis` / `secrets` / `network_security` / `permissions` sections; secrets routed through `redact_secret` |
| `grype`       | Anchore SCA / CVE matcher       | `matches[]`                               | `SUPPLY_CHAIN`                              | CVSSv3 anchored on highest-scoring vendor block; CWEs from `relatedVulnerabilities[]` (default CWE-1395) |

All ten parsers share a single house style:
`_normalise_severity` → `_classify_category` → `_make_finding` →
`_emit_with_dedup` → JSONL sidecar tagged with `tool_id`. Every
parser is fail-soft: malformed records emit a structured
`parser.malformed_record` `WARNING` and are skipped without crashing
the dispatch loop.

---

## 4. Implementation details

### 4.1 Shared helpers (`src/sandbox/parsers/_base.py`)

Two new helpers were lifted out of per-parser code into the shared
module so the redaction surface is auditable in one place and the
deduplication contract is consistent across the batch:

* `redact_secret(match: str | None, *, prefix: int, suffix: int) -> str | None`
  — keeps a configurable head/tail and replaces the middle with
  `***REDACTED({len})***`. Short strings collapse fully to the
  marker; `None` is preserved. Used by `gitleaks_parser` and the
  `mobsf` `secrets` section.
* `stable_hash_12(text: str) -> str` — deterministic, truncated
  SHA-256 hash for dedup-key stability across runs. Truncation is
  acceptable because the hash is a *dedup discriminator*, not a
  cryptographic primitive.

Both helpers are exported from `_base.py.__all__` and imported
explicitly by the new parsers — no wildcard imports anywhere in the
module.

### 4.2 Parser modules

Each parser lives at
`backend/src/sandbox/parsers/<tool>_parser.py` and exposes:

* `parse_<tool>_json(stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str) -> list[FindingDTO]`
* `EVIDENCE_SIDECAR_NAME: Final[str] = "<tool>_findings.jsonl"`

The 10 sidecar filenames are pinned-unique (asserted by
`test_arg021_tools_use_distinct_sidecar_filenames`) so a single
artifacts directory can hold the JSONL evidence of the entire batch
without overwrites — critical for shared-`/out` Kubernetes Job
volume layouts.

### 4.3 Dispatch wiring (`src/sandbox/parsers/__init__.py`)

`_DEFAULT_TOOL_PARSERS` grew by 10 entries (annotated with
`ARG-021` + Backlog §4.15/§4.16/§4.18 references). Every existing
registration (httpx, ffuf_dir, katana, wpscan, nuclei, nikto, wapiti,
trivy_image, trivy_fs, semgrep, sqlmap_safe, dalfox, interactsh_client,
nmap_*, …) is preserved — verified by
`test_arg021_does_not_drop_prior_cycle_registrations`.

### 4.4 Tests

* **Unit (`tests/unit/sandbox/parsers/test_<tool>_parser.py`)** —
  144 tests across 10 suites covering: empty / valid / malformed /
  no-tool-output / dedup / severity-mapping / category-routing /
  CWE extraction / sorting determinism / sidecar contents /
  fail-soft warning logging / canonical-file-vs-stdout precedence /
  redaction (gitleaks + mobsf secrets).
* **Integration (`tests/integration/sandbox/parsers/test_arg021_dispatch.py`)**
  — 35 cases:
  * registration sanity per tool,
  * `test_arg021_does_not_drop_prior_cycle_registrations`,
  * happy-path dispatch + sidecar tagging per tool,
  * sidecar-filename uniqueness,
  * **`test_gitleaks_redacts_secret_in_sidecar`** (security guardrail),
  * `test_gitleaks_finding_has_secret_leak_category`,
  * 6× cross-routing inertness pairs (defence in depth),
  * 10× determinism pairs,
  * `test_all_arg021_parsers_in_single_artifacts_dir_keeps_sidecars_intact`.
* **`tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py`** —
  `DEFERRED_ARG018_TOOL_IDS` trimmed to remove the 10 newly-wired
  tools. The remaining entries (openapi_scanner, graphw00f,
  clairvoyance, inql, graphql_cop, grpcurl_probe, postman_newman,
  prowler, scoutsuite, cloudsploit, pacu, syft, kube_hunter,
  trufflehog, detect_secrets) cover the §4.14/§4.15/§4.16 work that
  ARG-022 / ARG-029 will close in subsequent batches.

### 4.5 Documentation

`docs/tool-catalog.md` regenerated via
`python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md`.
Re-run with `--check` confirms zero drift. The "Parser coverage"
section now shows:

```
| **`mapped`**      | 43  | 27.39% |
| **`heartbeat`**   | 114 | 72.61% |
| **`binary_blob`** | 0   |  0.00% |
| **Total**         | 157 | 100.00% |
```

---

## 5. Verification

| Check                                                               | Command                                                                                          | Result          |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | --------------- |
| ARG-021 parser modules type-check                                   | `python -m mypy src/sandbox/parsers/`                                                            | **clean** (23 files) |
| ARG-021 parser modules + tests type-check                           | `python -m mypy src/sandbox/parsers/ tests/unit/sandbox/parsers/test_{ARG-021}_parser.py tests/integration/sandbox/parsers/test_{arg021,trivy_semgrep}_dispatch.py` | **clean** (24 files)¹ |
| ARG-021 parser modules + tests lint                                 | `python -m ruff check src/sandbox/parsers/ tests/unit/sandbox/parsers/ tests/integration/sandbox/parsers/` | **clean**       |
| ARG-021 format check                                                | `python -m ruff format --check src/sandbox/parsers/ tests/unit/sandbox/parsers/ tests/integration/sandbox/parsers/` | **clean** (59 files) |
| Per-parser unit tests (10 suites)                                   | `python -m pytest tests/unit/sandbox/parsers/test_{bandit,gitleaks,kube_bench,checkov,kics,terrascan,tfsec,dockle,mobsf,grype}_parser.py` | **144 passed** |
| ARG-021 integration suite                                           | `python -m pytest tests/integration/sandbox/parsers/test_arg021_dispatch.py`                     | **35 passed**   |
| Full sandbox dispatch surface                                       | `python -m pytest tests/integration/sandbox/parsers/`                                            | **233 passed**  |
| Coverage matrix gate                                                | `python -m pytest tests/test_tool_catalog_coverage.py`                                           | **clean**       |
| Docs in-sync drift guard                                            | `python -m scripts.docs_tool_catalog --check`                                                    | `check_ok tools=157` |
| Aggregated unit + sandbox-integration + catalog test surface        | `python -m pytest tests/unit tests/integration/sandbox tests/test_tool_catalog_coverage.py`      | **8049 passed** |

¹ Two pre-existing `mypy` errors in untracked sibling test files
(`tests/unit/sandbox/parsers/test_sqlmap_parser.py:422`,
`tests/unit/sandbox/parsers/test_dalfox_parser.py:439`) are out of
ARG-021 scope (created by prior cycles' work) and not regressions
introduced by this batch — verified by `git status --short`. ARG-021
files alone are mypy-clean.

---

## 6. Security guardrails

* **gitleaks raw-secret redaction** — enforced by integration test
  `test_gitleaks_redacts_secret_in_sidecar` against a realistic AWS
  Access Key Id fixture. Test asserts the literal secret is not
  present anywhere in the JSONL sidecar AND that the redaction
  marker is present.
* **mobsf secrets section redaction** — same `redact_secret` helper
  is wired into the `mobsf_parser` "secrets" section walk, so any
  upstream MoBSF report shape that surfaces credentials is masked
  before the FindingDTO leaves the parser.
* **Defensive parsing across all 10 tools** — every parser uses
  `safe_load_json` + per-record `try/except` + structured
  `WARNING parser.malformed_record` log. A malformed input slice
  never crashes the dispatch loop and never silently swallows the
  scan; it logs once and produces zero findings for the bad slice.
* **No CWE / CVSS / severity hard-coding outside the parser** — all
  per-tool mapping tables are local module constants, easy to audit
  in a single grep, and unit-tested with `≥10` cases per parser.
* **Cross-tool routing isolation** — 6 cross-routing cases prove
  that pushing payload from tool A through tool B's `tool_id`
  yields `[]`, never partial / corrupted FindingDTOs (defence in
  depth against shape-confusion attacks).

---

## 7. Non-regression

* All prior ARG-018 / Cycle 2 dispatch contracts intact:
  `test_trivy_semgrep_dispatch.py::test_arg018_does_not_drop_prior_cycle_registrations`
  PASS.
* All prior cycle parser surfaces (httpx, ffuf, katana, wpscan,
  nuclei, nikto, wapiti, trivy_image, trivy_fs, semgrep,
  sqlmap_safe, dalfox, interactsh_client, nmap_*) confirmed
  registered post-ARG-021 by `test_arg021_does_not_drop_prior_cycle_registrations`.
* Total descriptors held at 157 (long-term Backlog §4 target);
  catalog YAML/SIGNATURES untouched.
* `docs/tool-catalog.md` `--check` mode passes — committed doc is
  in sync with the regenerated output.

---

## 8. Known gaps (carry-over to ARG-022 / ARG-029)

ARG-021 intentionally focused on the JSON_OBJECT cluster; the
following remain on heartbeat fallback and are owned by subsequent
batches:

* **§4.15 / §4.16 deferred to ARG-029 (mixed JSON_OBJECT overflow):**
  `cloudsploit`, `prowler`, `scoutsuite`, `pacu`, `syft`,
  `kube_hunter`, `trufflehog`, `detect_secrets`.
* **§4.14 API/GraphQL deferred:** `openapi_scanner`, `graphw00f`,
  `clairvoyance`, `inql`, `graphql_cop`, `grpcurl_probe`,
  `postman_newman`.
* **§4.2 / §4.12 / §4.17 TEXT_LINES network/auth tools deferred to
  ARG-022:** `impacket_secretsdump`, `evil_winrm`, `kerbrute`,
  `bloodhound_python`, `snmpwalk`, `ldapsearch`, `smbclient_check`,
  `smbmap`, `enum4linux_ng`, `rpcclient_enum`.

After ARG-022 + ARG-029 the catalog should reach
≥63 / 157 mapped (target ≤89 heartbeat) per Cycle 3 plan.

Two pre-existing collection failures in the wider repo test surface
(`tests/test_argus010_sse_observability.py` SQLAlchemy aiosqlite
config drift; `tests/test_fix_004_cost_tracking.py` and
`tests/test_fix_006_recon.py` `ImportError`s for symbols that no
longer exist) and a `auth_bypass.yaml` SIGNATURES drift in
`backend/config/payloads/` are **NOT** part of ARG-021 scope —
they are carried over from earlier cycles and will be addressed
either in ARG-030 capstone or in their respective re-sign / DB
migration tasks.

---

## 9. Files changed

```
backend/src/sandbox/parsers/_base.py                                  (modify: +redact_secret, +stable_hash_12)
backend/src/sandbox/parsers/bandit_parser.py                          (new)
backend/src/sandbox/parsers/gitleaks_parser.py                        (new)
backend/src/sandbox/parsers/kube_bench_parser.py                      (new)
backend/src/sandbox/parsers/checkov_parser.py                         (new)
backend/src/sandbox/parsers/kics_parser.py                            (new)
backend/src/sandbox/parsers/terrascan_parser.py                       (new)
backend/src/sandbox/parsers/tfsec_parser.py                           (new)
backend/src/sandbox/parsers/dockle_parser.py                          (new)
backend/src/sandbox/parsers/mobsf_parser.py                           (new)
backend/src/sandbox/parsers/grype_parser.py                           (new)
backend/src/sandbox/parsers/__init__.py                               (modify: +10 imports + 10 dispatch entries + ARG-021 docstring block)
backend/tests/unit/sandbox/parsers/test_bandit_parser.py              (new)
backend/tests/unit/sandbox/parsers/test_gitleaks_parser.py            (new)
backend/tests/unit/sandbox/parsers/test_kube_bench_parser.py          (new)
backend/tests/unit/sandbox/parsers/test_checkov_parser.py             (new)
backend/tests/unit/sandbox/parsers/test_kics_parser.py                (new)
backend/tests/unit/sandbox/parsers/test_terrascan_parser.py           (new)
backend/tests/unit/sandbox/parsers/test_tfsec_parser.py               (new)
backend/tests/unit/sandbox/parsers/test_dockle_parser.py              (new)
backend/tests/unit/sandbox/parsers/test_mobsf_parser.py               (new)
backend/tests/unit/sandbox/parsers/test_grype_parser.py               (new)
backend/tests/integration/sandbox/parsers/test_arg021_dispatch.py     (new)
backend/tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py
                                                                       (modify: trim DEFERRED_ARG018_TOOL_IDS by the 10 wired tools + add ARG-021 cross-reference comment)
docs/tool-catalog.md                                                  (regenerated; mapped=43, heartbeat=114, binary_blob=0)
ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md         (modify: ARG-021 status → ✅ Completed; acceptance bullets ticked; progress table updated)
ai_docs/develop/reports/2026-04-19-arg-021-parsers-batch1-report.md   (new — this file)
```

---

## 10. Sign-off

ARG-021 — Per-tool parsers batch 1 (JSON_OBJECT IaC/SAST/Cloud, 10) —
**Completed** on 2026-04-19. Mapped parser count grew from 33 → 43
(+30 %); heartbeat fallback dropped from 124 → 114 (–8 %). All
acceptance criteria met, no regressions in adjacent dispatch suites,
gitleaks raw-secret redaction enforced by dedicated CI guardrail.

Ready for hand-off to ARG-022 (TEXT_LINES network/auth batch) and
ARG-029 (parsers batch 3 — JSON_LINES + custom).
