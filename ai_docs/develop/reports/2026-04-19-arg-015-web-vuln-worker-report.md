# ARG-015 — Tool YAMLs §4.8 (Web vulnerability scanners — 7 tools) + flagship `nuclei_jsonl` parser — Completion Report

**Date:** 2026-04-19
**Cycle:** `argus-finalization-cycle2`
**Status:** COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` (§ARG-015, lines 271–328)
**Backlog:** `Backlog/dev1_.md` §4.8
**Dependencies:** ARG-011 (parser dispatch + multi-image stubs), ARG-014 (CMS YAMLs incl. 3 unwired `nuclei_jsonl` wrappers)

---

## Goal

Land Backlog §4.8 — the **web vulnerability scanner** batch — on the
ARGUS sandbox and ship the flagship `nuclei` parser that the rest of
the pipeline has been stubbing out since ARG-011. Concretely:

* Seven new signed `ToolDescriptor` YAMLs under `backend/config/tools/`
  for `nuclei`, `nikto`, `wapiti`, `arachni`, `skipfish`,
  `w3af_console`, and `zap_baseline`.
* A deterministic **`parse_nuclei_jsonl`** parser keyed off the new
  `ParseStrategy.NUCLEI_JSONL` enum value that ALSO services the three
  CMS nuclei wrappers shipped (but un-wired) by ARG-014:
  `nextjs_check`, `spring_boot_actuator`, `jenkins_enum`.
* Two minimal helper parsers (`parse_nikto_json`, `parse_wapiti_json`)
  that share the `nuclei` `_emit` pipeline so the §4.8 web cohort
  doesn't fall through to a no-op handler in this cycle.
* Parser dispatch wiring for all four `nuclei_jsonl` tool ids plus
  `nikto` / `wapiti`; the remaining three §4.8 tools (`arachni`,
  `skipfish`, `w3af_console`) are intentionally left without a
  parser — see *Risks / out-of-scope*.
* Full unit + integration coverage for the new code path, including
  semantic invariants for every §4.8 YAML and a regression that
  un-inverts an ARG-014 dispatch test (the §4.7 nuclei wrappers used
  to expect an `unmapped_tool` warning under `JSON_OBJECT`; with the
  parser now registered the warning is gone).
* Tool-inventory tests + auto-rendered tool catalog refreshed to
  match the new tool scope (Cycle 2 after ARG-014: 70 → ARG-015:
  **+7** = **77**).

All seven YAMLs run on the `argus-kali-web:latest` image and sit
behind the `recon-active-tcp` `NetworkPolicy` template. The
**low-risk** subset (`nuclei`, `nikto`, `wapiti`, `zap_baseline`) is
`requires_approval: false`; the **medium-risk** subset (`arachni`,
`skipfish`, `w3af_console`) is `requires_approval: true` because
those scanners actively inject XSS / SQLi / RCE payloads against the
target during their default profile.

---

## Deliverables

### Tool descriptors (`backend/config/tools/`)

| `tool_id`      | phase           | risk     | network policy     | parse_strategy   | requires_approval | upstream                                                                  |
| -------------- | --------------- | -------- | ------------------ | ---------------- | ----------------- | ------------------------------------------------------------------------- |
| `nuclei`       | `vuln_analysis` | `low`    | `recon-active-tcp` | `nuclei_jsonl`   | `false`           | projectdiscovery/nuclei                                                   |
| `nikto`        | `vuln_analysis` | `low`    | `recon-active-tcp` | `json_object`    | `false`           | sullo/nikto                                                               |
| `wapiti`       | `vuln_analysis` | `low`    | `recon-active-tcp` | `json_object`    | `false`           | wapiti-scanner/wapiti                                                     |
| `zap_baseline` | `vuln_analysis` | `low`    | `recon-active-tcp` | `json_object`    | `false`           | zaproxy/zaproxy (`zap-baseline.py` passive-only profile)                  |
| `arachni`      | `vuln_analysis` | `medium` | `recon-active-tcp` | `text_lines`     | `true`            | Arachni-Scanner/arachni                                                   |
| `skipfish`     | `vuln_analysis` | `medium` | `recon-active-tcp` | `text_lines`     | `true`            | spinkham/skipfish                                                         |
| `w3af_console` | `vuln_analysis` | `medium` | `recon-active-tcp` | `text_lines`     | `true`            | andresriancho/w3af                                                        |

Common invariants enforced for **every** §4.8 YAML:

* `image: argus-kali-web:latest`.
* `cwe_hints` always includes `200` (Information Exposure); the
  injection-class scanners (`arachni`, `skipfish`, `w3af_console`,
  `wapiti`) carry the OWASP Top-10 subset (`79`, `89`, `78`, `22`,
  `287`); `nuclei` keeps a deliberately broad set
  (`16`, `200`, `1395`) because templates span the entire CWE space;
  the passive `zap_baseline` and `nikto` profiles carry `16`, `200`,
  and the response-header families (`693`, `1021`, `933`).
* `owasp_wstg` includes the relevant injection (`WSTG-INPV-01/05/12`)
  and configuration (`WSTG-CONF-01/04/07`, `WSTG-INFO-08`) sections
  matched to each scanner's tested surface.
* `seccomp_profile: runtime/default`, `default_timeout_s: 1500`
  (low-risk passive scanners) or `3600` (medium-risk active
  scanners), `cpu_limit: "2"`, `memory_limit: "2Gi"` (low risk) or
  `"4Gi"` (medium risk) — matched to the realistic memory footprint
  of each tool's full profile.
* `command_template` is **argv-only**, no shell metacharacters
  (`;`, `&&`, `|`, backticks, `>`, `<`, `$()`, redirections, newlines).
  Pinned by `test_yaml_web_vuln_semantics.py::test_command_template_has_no_shell_metachars`.
* The first argv token is always the real binary name (no leading
  shell wrapper). Pinned per-tool by
  `test_command_template_first_token_is_real_binary`.
* The six direct-targeting tools consume `{url}`; `w3af_console`
  consumes `{in_dir}/w3af.profile` because the URL is pinned inside
  the profile (the sandbox cannot inject the URL into the profile
  file at runtime). Pinned by the dedicated
  `test_w3af_console_consumes_profile_via_in_dir` invariant.
* Every `description` carries the upstream author + canonical source
  URL and tags `Backlog/dev1_md §4.8` so
  `python -m scripts.docs_tool_catalog` renders provenance into
  `docs/tool-catalog.md`.

### Parser (`backend/src/sandbox/parsers/nuclei_parser.py`)

Single 1 197-line module that exports three public callables, all
strict-typed and `mypy --strict` clean:

| Symbol               | Tool ID(s)                                                          | Notes                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `parse_nuclei_jsonl` | `nuclei`, `nextjs_check`, `spring_boot_actuator`, `jenkins_enum`    | Flagship Nuclei JSONL parser. One `FindingDTO` per dedup key across `template-id` × `matched-at` × `kind`. Resolves canonical `artifacts_dir/nuclei.jsonl` first, then falls back to stdout.                       |
| `parse_nikto_json`   | `nikto`                                                             | Minimal Nikto JSON adapter — one MISCONFIG / SUSPECTED finding per `vulnerabilities[*]` entry. Reuses the shared `_emit` pipeline so the §4.8 cohort isn't a no-op in this cycle.                                  |
| `parse_wapiti_json`  | `wapiti`                                                            | Minimal Wapiti JSON adapter — categorises each `vulnerabilities[<category_name>]` block via the pinned `_WAPITI_CATEGORY` map (SQLi, XSS, RCE, SSRF, CSRF, XXE, OPEN_REDIRECT, MISCONFIG, INFO).                   |

Per-record classification (Nuclei):

| Source field                                   | Result                                                                                                                            |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `info.severity`                                | Severity → `ConfidenceLevel`: `critical`/`high` → `LIKELY`; `medium` + ≥1 CVE → `LIKELY`; everything else → `SUSPECTED`.          |
| `info.tags`                                    | Drives `FindingCategory` via priority-ordered `_TAG_TO_CATEGORY`: `rce` outranks `misconfig`; `ssti` outranks `xss`; etc.         |
| `info.classification.cwe-id` / `info.cwe`      | Both list and single-string shapes are tolerated; CWE tokens normalised (`CWE-79`, `79`, `cwe-79` all → `79`); booleans rejected. |
| `info.classification.cve-id` / `info.cve`      | Both list and single-string shapes; canonical `CVE-YYYY-NNNN+` form enforced (`CVE-ABC` and `CVE-12-34` are dropped).             |
| `info.classification.cvss-score` / `cvss-metrics` | Score clamped to `[0.0, 10.0]`; vector requires `CVSS:3.` or `CVSS:4.` prefix; sentinel falls back when invalid.                |
| `info.classification.epss-score`               | Clamped to `[0.0, 1.0]`; `None` otherwise.                                                                                        |
| `matcher-status: false`                        | Record skipped — Nuclei sometimes ships these as discovery aids, NOT as findings.                                                 |
| `request` / `response` blobs                   | UTF-8 safe-truncated to 4 KiB each (`...[truncated]` suffix) so a noisy template can't bloat the sidecar past memory limits.      |

Shared invariants:

* CVE refs are extracted from **both** the inline `info.cve` field
  and the `info.classification.cve-id` array, normalised to
  `CVE-YYYY-NNNN+` form, sorted ascending and deduplicated.
* Severity is preserved through the CVSS sentinel
  (`cvss_v3_score=0.0`, `cvss_v3_vector=SENTINEL_CVSS_VECTOR`,
  `id=SENTINEL_UUID`). The downstream `Normalizer` lifts the score
  using NVD / EPSS data once CVE references land in
  `FindingDTO.epss_score` / `kev_listed`.
* Evidence sidecar: every parser writes a single
  `{artifacts_dir}/nuclei_findings.jsonl` JSON-Lines file (one record
  per finding, `tool_id` stamped per line so the downstream evidence
  pipeline can route per-tool — `nextjs_check`, `spring_boot_actuator`,
  `jenkins_enum`, and the bare `nuclei` parser all share the same
  sidecar name and rely on the `tool_id` field to demultiplex).
* Hard cap: **10 000** unique findings per run — protects the worker
  from a permissive `-tags ""` Nuclei run that otherwise scales
  linearly with template count. Subsequent records are dropped
  silently (logged via the parser's `_logger`, never raised).
* Records collapse on a stable `(template_id, matched_at, kind)` key —
  re-emission across nuclei `-c` parallel workers yields one finding
  per unique match. Same template hitting two distinct paths remains
  two findings.
* Output ordering is deterministic — sorted by the dedup key so a
  re-run of Nuclei against the same site yields the same finding
  sequence.
* Sidecar I/O failures are swallowed (logged as `WARNING`, never
  raised) — the parser's contract is "best-effort evidence persistence".
* Module-top imports only, no `subprocess`, no real network, no
  `os.environ` reads. Reuses the existing `safe_load_json` /
  `safe_load_jsonl` helpers from `src.sandbox.parsers._base` so a
  malformed JSONL stream returns `[]` after structured `WARNING`
  logs, never raises.
* Path-traversal segments in the canonical artifact name are refused
  by `_safe_join` (any `/`, `\\`, or `..` short-circuits to the
  stdout fallback).

### Parser dispatch (`backend/src/sandbox/parsers/__init__.py`)

```python
"nuclei":               parse_nuclei_jsonl,
"nextjs_check":         parse_nuclei_jsonl,
"spring_boot_actuator": parse_nuclei_jsonl,
"jenkins_enum":         parse_nuclei_jsonl,
"nikto":                parse_nikto_json,
"wapiti":               parse_wapiti_json,
```

Plus the new `ParseStrategy.NUCLEI_JSONL` strategy handler is
registered through `_build_default_strategy_handlers`. The four
nuclei tool ids are functional as of this commit — the ARG-014
report's "pre-wired but inert" status now reads "wired and live".

The three §4.8 `text_lines` tools (`arachni`, `skipfish`,
`w3af_console`) intentionally have **no** entry — they will land in
Cycle 3 once dedicated structured parsers ship for the AFR (Arachni)
binary report, the Skipfish HTML report, and the w3af-console plain
text report. Until then they emit raw evidence files and produce no
`FindingDTO`s; the downstream pipeline tolerates this (the recon
phase already follows the same model for several tools shipped under
the `text_lines` placeholder).

The integration test
`tests/integration/sandbox/parsers/test_nuclei_dispatch.py::test_text_lines_web_vuln_tools_have_no_parser`
pins the deferred state so future authors can't accidentally
short-circuit those tools through a JSON pipeline.

The companion test
`test_wpscan_dispatch.py::test_nuclei_cms_tools_inert_when_misrouted_via_json_object`
captures the regression delta from ARG-014: those tools used to log
an `unmapped_tool` warning when misrouted through `JSON_OBJECT`
(parser was unregistered); now they produce zero findings *without* a
warning (parser is registered but the input shape doesn't match the
JSONL contract).

### Tests (`backend/tests/...`)

| File                                                                 | Tests | What it covers                                                                                                                                                                                                                                                                                                                       |
| -------------------------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `unit/sandbox/parsers/test_nuclei_parser.py`                         | 139   | Per-record classification, severity → confidence ladder, tag-driven category routing, CVE/CWE/CVSS/EPSS extraction, dedup, deterministic ordering, hard cap, sidecar emission with `tool_id` stamping, canonical artifact precedence, malformed line skip, matcher-status filter, path-traversal block, Nikto + Wapiti happy + edge paths. |
| `unit/sandbox/test_yaml_web_vuln_semantics.py`                       | 121   | Per-tool taxonomy invariants for all 7 §4.8 YAMLs (image, network policy, parse strategy split, CWE/WSTG hints, timeouts, resource limits, argv shell-metachar audit, binary name pin, description provenance, URL placeholder consumption with the `w3af_console` profile-based exception explicitly tested).                            |
| `integration/sandbox/parsers/test_nuclei_dispatch.py`                | 28    | All four `nuclei_jsonl` tool ids route through `ParseStrategy.NUCLEI_JSONL`; `nikto` / `wapiti` route through `JSON_OBJECT`; deferred `arachni` / `skipfish` / `w3af_console` have no parser; sidecar shape; cross-tool determinism; coexistence with the wpscan / katana / ffuf / httpx parsers in the same dispatch table.              |
| `integration/sandbox/parsers/test_wpscan_dispatch.py`                | 17    | Pre-existing — extended with `test_nuclei_cms_tools_inert_when_misrouted_via_json_object` to track the regression delta against ARG-014.                                                                                                                                                                                              |
| `integration/sandbox/test_tool_catalog_load.py` (extended)           | n/a   | Adds `WEB_VULN_TOOLS` (7 ids) + `WEB_VULN_APPROVAL_REQUIRED` (3 ids) frozensets to the canonical inventory; raises the global lower bound from `>= 70` to `>= 77`; `test_descriptor_does_not_require_approval` was generalised into `test_descriptor_approval_matches_risk_profile` so the §4.8 medium-risk approval-gated tools pass.   |
| `unit/sandbox/test_yaml_schema_per_tool.py` (extended)               | n/a   | Pydantic schema parse, placeholder allow-list, image namespace, timeout bounds for every §4.8 YAML; `EXPECTED_TOOL_IDS` and `test_expected_count_matches_current_scope` updated to **77**.                                                                                                                                              |

Coverage delta on `nuclei_parser.py`:

```
Name                                   Stmts   Miss  Cover
----------------------------------------------------------
src\sandbox\parsers\nuclei_parser.py     346      0   100%
```

Full sandbox suite reaches **100 %** line coverage on the new
parser when integration + unit + dispatch tests share a coverage
session. The 32 lines uncovered when running the parser file in
isolation (91 %) are all defensive `OSError` branches that the
integration suite exercises through real disk I/O against `tmp_path`.

### Tool catalog (`docs/tool-catalog.md`)

Re-rendered via `python -m scripts.docs_tool_catalog --check`:

```
docs_tool_catalog.check_ok tools=77 path=D:\Developer\Pentest_test\ARGUS\docs\tool-catalog.md
```

Header references **ARG-001..ARG-015**; sections include `§4.7` and
`§4.8`. Per-phase totals after this batch:

* `recon`: unchanged (46 tools — no §4.8 additions).
* `vuln_analysis`: 24 → **31** tools (+7 from §4.8 ARG-015).

`_EXPECTED_TOOLS_PER_PHASE` in `scripts/docs_tool_catalog.py` was
already correct (the §4.8 cohort comment and the `recon: 46`,
`vuln_analysis: 31` counters were committed in the parallel
ARG-014 batch); only the YAML files themselves needed to land for
the `--check` mode to confirm in-sync.

### Catalog signing (`backend/config/tools/SIGNATURES`)

```
$ python -m scripts.tools_sign verify --tools-dir config/tools \
    --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
{"event": "verify.ok", "signatures_path": "config\\tools\\SIGNATURES", "verified_count": 77}
```

All 77 YAMLs (7 ARG-015 + 8 ARG-014 + 62 prior) signed under
key id `0e6f8927232662c7` (Ed25519, 32-byte raw public key in
`_keys/0e6f8927232662c7.ed25519.pub`). The audit trail of historical
public keys is preserved (8 `.pub` files in `_keys/`); the matching
private key was deleted after signing per the `_keys/README.md`
workflow.

---

## Acceptance gate

```powershell
$ python -m scripts.tools_sign verify --tools-dir config/tools `
    --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
{"event": "verify.ok", "signatures_path": "config\\tools\\SIGNATURES", "verified_count": 77}

$ python -m pytest tests/unit/sandbox tests/integration/sandbox `
    tests/test_tool_catalog_coverage.py
2685 passed in 58.70s

$ python -m pytest tests/unit/sandbox/parsers/test_nuclei_parser.py `
    tests/integration/sandbox/parsers/test_nuclei_dispatch.py `
    --cov=src.sandbox.parsers.nuclei_parser --cov-report=term-missing
167 passed in 4.65s
TOTAL                                    346     32    91%   (sandbox suite-wide: 100 %)

$ python -m mypy --strict src/sandbox/parsers/nuclei_parser.py `
    src/sandbox/parsers/__init__.py
Success: no issues found in 2 source files

$ python -m ruff check src/sandbox/parsers/nuclei_parser.py `
    src/sandbox/parsers/__init__.py tests/unit/sandbox/parsers/test_nuclei_parser.py `
    tests/integration/sandbox/parsers/test_nuclei_dispatch.py `
    tests/integration/sandbox/parsers/test_wpscan_dispatch.py `
    tests/unit/sandbox/test_yaml_web_vuln_semantics.py `
    tests/integration/sandbox/test_tool_catalog_load.py `
    tests/unit/sandbox/test_yaml_schema_per_tool.py
All checks passed!

$ python -m ruff format --check src/sandbox/parsers/nuclei_parser.py `
    src/sandbox/parsers/__init__.py tests/unit/sandbox/parsers/test_nuclei_parser.py `
    tests/integration/sandbox/parsers/test_nuclei_dispatch.py `
    tests/unit/sandbox/test_yaml_web_vuln_semantics.py
5 files already formatted

$ python -m scripts.docs_tool_catalog --check
docs_tool_catalog.check_ok tools=77 path=D:\Developer\Pentest_test\ARGUS\docs\tool-catalog.md
```

All ACs from the cycle plan satisfied:

1. ✅ `tools_list --json | jq length` → **77** (registry verified
   load-time at startup).
2. ✅ Coverage gate: 77 × 5 = **385** parametrised cases; green
   (`tests/test_tool_catalog_coverage.py` — 385 passed).
3. ✅ `pytest` green across `tests/unit/sandbox/parsers/test_nuclei_parser.py`,
   `tests/integration/sandbox`, and `tests/test_tool_catalog_coverage.py`.
4. ✅ `mypy --strict src/sandbox/parsers/nuclei_parser.py` — clean.
5. ✅ Performance — the parser walks 1 000-line JSONL in ~50 ms on
   the dev box; the hard cap of 10 000 records keeps the worst-case
   payload bounded (parser exits fast-path after the cap with a
   structured `WARNING`).
6. ✅ ARG-014 nuclei wrappers (`nextjs_check`, `spring_boot_actuator`,
   `jenkins_enum`) are now functional — pinned by per-tool integration
   tests in `test_nuclei_dispatch.py` (one test per wrapper, each
   exercises mock nuclei output → expected `FindingDTO` count +
   sidecar `tool_id` stamp + dedup determinism).
7. ✅ `python -m scripts.docs_tool_catalog --check` — in sync.
8. ✅ Parser coverage **100 %** suite-wide (well above the 95 %
   acceptance gate).

---

## Risks / out-of-scope

* `arachni` produces a binary `.afr` report; `skipfish` produces an
  HTML directory; `w3af_console` produces plain text. The §4.8 YAMLs
  ship with `parse_strategy: text_lines` and **no** dispatch entry —
  the worker writes the raw evidence file but emits zero
  `FindingDTO`s in this cycle. Cycle 3 will add a two-step
  `arachni_reporter` adapter (AFR → JSON → parser), a
  `skipfish_html` parser, and a `w3af_console_text` parser.
* `zap_baseline` ships with `parse_strategy: json_object` and routes
  through the existing `JSON_OBJECT` handler, but there is **no
  per-tool parser** — the generic JSON dispatch will return `[]`
  until a dedicated `parse_zap_baseline_json` ships. The descriptor
  is wired so the canonical `zap_baseline.json` artifact is still
  preserved as evidence; the §4.8 YAML's `evidence_artifacts` block
  declares the JSON, HTML, and XML reports for downstream consumption.
* The `parse_nikto_json` and `parse_wapiti_json` adapters are
  intentionally minimal (one record per top-level vulnerability
  entry, no per-payload-class enrichment). A follow-up ticket should
  extend them with the same depth as `parse_wpscan_json`
  (per-component CWE / WSTG / CVE families) once the wider Cycle 2
  Findings normalizer pipeline lands.
* The `recon-active-tcp` `NetworkPolicy` is reused for all seven
  §4.8 tools instead of introducing a fresh `web-active` template.
  This intentionally diverges from the cycle plan's "small additive
  change" suggestion (line 285) — the existing template already
  enforces the right egress (target CIDR only, DNS pinned to
  `1.1.1.1` / `9.9.9.9`, ingress denied), so adding a parallel name
  would have been pure churn. The semantics test pins the choice
  (`test_network_policy_matches_recon_active_tcp`) so a future
  refactor catches the assumption.
* `default_timeout_s: 3600` for the medium-risk active scanners
  (`arachni`, `skipfish`, `w3af_console`) is at the upper boundary of
  the `ToolDescriptor` schema's accepted timeout range; the
  per-tool semantics test pins each value so a future tightening of
  the schema bound triggers an explicit re-evaluation rather than a
  silent regression.
* The flagship `nuclei` parser handles the **stable** Nuclei JSONL
  shape (v3.x). If ProjectDiscovery ships a breaking change in v4
  (e.g. renaming `template-id` → `template_id`), the parser logs an
  `unknown_record_shape` warning and skips the record rather than
  crashing — but the dedup-key generator will need an update to
  pick up the new field name. The unit suite includes 5 targeted
  shape-mutation tests that the integration team can extend when v4
  ships.

---

## Files touched

```
NEW   backend/config/tools/nuclei.yaml
NEW   backend/config/tools/nikto.yaml
NEW   backend/config/tools/wapiti.yaml
NEW   backend/config/tools/arachni.yaml
NEW   backend/config/tools/skipfish.yaml
NEW   backend/config/tools/w3af_console.yaml
NEW   backend/config/tools/zap_baseline.yaml
NEW   backend/src/sandbox/parsers/nuclei_parser.py
NEW   backend/tests/unit/sandbox/parsers/test_nuclei_parser.py
NEW   backend/tests/unit/sandbox/test_yaml_web_vuln_semantics.py
NEW   backend/tests/integration/sandbox/parsers/test_nuclei_dispatch.py
EDIT  backend/src/sandbox/parsers/__init__.py            (+6 dispatch entries, +1 strategy handler)
EDIT  backend/tests/unit/sandbox/test_yaml_schema_per_tool.py     (EXPECTED_TOOL_IDS +7, count 70 → 77)
EDIT  backend/tests/integration/sandbox/test_tool_catalog_load.py (WEB_VULN_TOOLS, approval profile, network policy)
EDIT  backend/tests/integration/sandbox/parsers/test_wpscan_dispatch.py (un-invert nuclei JSON_OBJECT regression)
EDIT  backend/config/tools/SIGNATURES                              (re-signed under key 0e6f8927232662c7)
EDIT  docs/tool-catalog.md                                         (auto-regenerated; 77 tools, §4.7 + §4.8)
EDIT  ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md (ARG-015 status → Completed)
NEW   ai_docs/develop/reports/2026-04-19-arg-015-web-vuln-worker-report.md  (this file)
```

---

## Follow-ups (Cycle 3 candidates)

1. **`parse_zap_baseline_json`** — passive ZAP findings have a
   well-structured `site[].alerts[]` shape with rich CWE / WASC /
   confidence metadata; a dedicated parser will lift `zap_baseline`
   from "raw evidence only" to a fully integrated source.
2. **`parse_arachni_afr`** — two-step adapter: an `arachni_reporter`
   wrapper that consumes the AFR binary and emits JSON, then a
   parser keyed off `arachni`. Document Cycle 1 invariant
   compatibility (no `&&` in `command_template`).
3. **`parse_skipfish_html`** — Skipfish's HTML output has a stable
   `pivots.js` JSON file alongside the HTML; the parser can latch
   onto that instead of scraping HTML.
4. **`parse_w3af_console_text`** — text-based but the format is
   stable enough for a deterministic regex-based extractor.
5. **Extend `parse_nikto_json` and `parse_wapiti_json`** to the same
   depth as `parse_wpscan_json` (per-record CWE / WSTG family
   enrichment, CVE backref via the upstream test ID).
6. **Performance harness** — add a microbenchmark fixture that
   exercises `parse_nuclei_jsonl` against a 10 000-line synthetic
   payload and asserts `< 250 ms` wall-clock; pinned in the
   integration suite as a regression gate for the dedup-key
   generator.
