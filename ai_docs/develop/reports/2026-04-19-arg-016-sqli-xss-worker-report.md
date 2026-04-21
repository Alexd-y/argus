# ARG-016 — Tool YAMLs §4.9 SQLi (6) + §4.10 XSS (5) = 11 + `sqlmap_output` + `dalfox_json` parsers — Completion Report

**Date:** 2026-04-19
**Cycle:** `argus-finalization-cycle2`
**Status:** COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` (§ARG-016, lines 332–384)
**Backlog:** `Backlog/dev1_.md` §4.9 + §4.10
**Dependencies:** ARG-005 (PayloadRegistry — sqlmap/dalfox use payload families), ARG-006 (PolicyEngine — `sqlmap_confirm` requires approval), ARG-015 (parser pattern, `_emit` pipeline, sidecar contract)

---

## Goal

Land Backlog §4.9 (active SQL-injection scanners) + §4.10 (Cross-Site
Scripting scanners) on the ARGUS sandbox and ship the two flagship
text/JSON parsers (`sqlmap_output`, `dalfox_json`) the rest of the
pipeline has been stubbing out since ARG-011. Concretely:

* Eleven new signed `ToolDescriptor` YAMLs under
  `backend/config/tools/` — six SQLi (`sqlmap_safe`, `sqlmap_confirm`,
  `ghauri`, `jsql`, `tplmap`, `nosqlmap`) + five XSS (`dalfox`,
  `xsstrike`, `kxss`, `xsser`, `playwright_xss_verify`).
* A deterministic **`parse_sqlmap_output`** parser keyed off a brand
  new `ParseStrategy.TEXT_LINES` strategy handler (sqlmap is the
  first text-line-based parser to land in the registry).
* A deterministic **`parse_dalfox_json`** parser routed through the
  existing `ParseStrategy.JSON_OBJECT` handler with a per-tool
  override so `dalfox.json` envelopes don't fall through to the
  generic JSON dispatch.
* Parser dispatch wiring for `sqlmap_safe`, `sqlmap_confirm` and
  `dalfox`; the remaining eight tools (`ghauri`, `jsql`, `tplmap`,
  `nosqlmap`, `xsstrike`, `kxss`, `xsser`, `playwright_xss_verify`)
  are intentionally left without a parser entry — see
  *Risks / out-of-scope*.
* Full unit + integration + e2e + semantic coverage for the new code
  paths, plus a small regression in `test_dispatch_registry.py` that
  pins the new `TEXT_LINES` strategy in the default registry.
* Tool-inventory tests + auto-rendered tool catalog refreshed to
  match the new tool scope (Cycle 2 after ARG-015: 77 → ARG-016:
  **+11** = **88**).

All SQLi/XSS tools (except `playwright_xss_verify`) run on the
`argus-kali-web:latest` image and sit behind the
`recon-active-tcp` `NetworkPolicy` template. The sole
`argus-kali-browser:latest` consumer is `playwright_xss_verify`,
which is mapped onto the **`exploitation`** phase (Backlog requests
`validation`, but Cycle 1's `ScanPhase` enum has no `validation`
member; `exploitation` + `risk_level: low` keeps it approval-free).

The **passive / low-risk** subset (`sqlmap_safe`, `dalfox`,
`xsstrike`, `kxss`, `xsser`, `playwright_xss_verify`) is
`requires_approval: false`. The **medium / high-risk** subset
(`sqlmap_confirm`, `ghauri`, `jsql`, `tplmap`, `nosqlmap`) is
`requires_approval: true` because those scanners actively inject
real SQLi / SSTI / NoSQLi payloads against the target during their
default profile.

---

## Deliverables

### Tool descriptors (`backend/config/tools/`)

| `tool_id`               | phase           | risk     | network policy     | parse_strategy   | requires_approval | image                       | upstream                                                |
| ----------------------- | --------------- | -------- | ------------------ | ---------------- | ----------------- | --------------------------- | ------------------------------------------------------- |
| `sqlmap_safe`           | `vuln_analysis` | `low`    | `recon-active-tcp` | `text_lines`     | `false`           | `argus-kali-web:latest`     | sqlmapproject/sqlmap                                    |
| `sqlmap_confirm`        | `exploitation`  | `high`   | `recon-active-tcp` | `text_lines`     | **`true`**        | `argus-kali-web:latest`     | sqlmapproject/sqlmap                                    |
| `ghauri`                | `vuln_analysis` | `medium` | `recon-active-tcp` | `text_lines`     | `true`            | `argus-kali-web:latest`     | r0oth3x49/ghauri                                        |
| `jsql`                  | `vuln_analysis` | `medium` | `recon-active-tcp` | `json_object`    | `true`            | `argus-kali-web:latest`     | ron190/jsql-injection                                   |
| `tplmap`                | `vuln_analysis` | `high`   | `recon-active-tcp` | `text_lines`     | `true`            | `argus-kali-web:latest`     | epinna/tplmap                                           |
| `nosqlmap`              | `vuln_analysis` | `medium` | `recon-active-tcp` | `text_lines`     | `true`            | `argus-kali-web:latest`     | codingo/NoSQLMap                                        |
| `dalfox`                | `vuln_analysis` | `low`    | `recon-active-tcp` | `json_object`    | `false`           | `argus-kali-web:latest`     | hahwul/dalfox                                           |
| `xsstrike`              | `vuln_analysis` | `low`    | `recon-active-tcp` | `json_object`    | `false`           | `argus-kali-web:latest`     | s0md3v/XSStrike                                         |
| `kxss`                  | `vuln_analysis` | `passive`| `recon-active-tcp` | `text_lines`     | `false`           | `argus-kali-web:latest`     | Emoe/kxss (Tom Hudson)                                  |
| `xsser`                 | `vuln_analysis` | `low`    | `recon-active-tcp` | `json_object`    | `false`           | `argus-kali-web:latest`     | epsylon/xsser                                           |
| `playwright_xss_verify` | `exploitation`  | `low`    | `recon-active-tcp` | `json_object`    | `false`           | `argus-kali-browser:latest` | ARGUS team (in-house wrapper around playwright.dev)     |

Common invariants enforced for **every** §4.9/§4.10 YAML:

* `cwe_hints` carries the right CWE family per tool:
  * SQLi tools (`sqlmap_safe`, `sqlmap_confirm`, `ghauri`, `jsql`) →
    `[89, 564, 943]` (CWE-89 SQL Injection + 564 ORM injection + 943
    NoSQL/blind-style injection coverage).
  * `tplmap` → `[1336, 94, 78]` (SSTI + Code Injection + OS Command
    Injection — `tplmap` is **not** an SQLi tool despite the §4.9
    grouping; the CWE pin reflects its real attack surface).
  * `nosqlmap` → `[943, 89, 287]` (NoSQL injection + SQLi-adjacent
    + auth bypass that NoSQLMap actively probes).
  * XSS tools all carry `[79]` plus per-tool extras
    (`80` for filter-bypass, `87` for alt-syntax XSS, `116` for
    improper encoding contexts).
* `owasp_wstg` includes the matched **INPV** sections — `WSTG-INPV-05`
  for SQLi, `WSTG-INPV-06` for SSTI, `WSTG-INPV-01/02` for XSS. The
  semantic test pins the family per tool (no escaped/typo'd
  identifiers).
* `seccomp_profile: runtime/default`, `default_timeout_s: 1800` for
  the `sqlmap_*` variants (long iterative DBMS enumeration), `900`
  for everything else (single-pass scanners), `cpu_limit: "1"`,
  `memory_limit: "1Gi"` (or `"2Gi"` for `playwright_xss_verify` which
  ships a headless Chromium with the runtime).
* `command_template` is **argv-only**, no shell metacharacters
  (`;`, `&&`, `|`, backticks, `>`, `<`, `$()`, redirections, newlines).
  Pinned by `test_yaml_sqli_semantics.py` and
  `test_yaml_xss_semantics.py`.
* The first argv token is always the real binary name (no leading
  shell wrapper). For `kxss`, `playwright_xss_verify`, `tplmap`,
  `nosqlmap`, `jsql` the canonical binary is a thin runner script
  shipped under `/usr/local/bin/{tool}-runner` because the upstream
  CLIs are interactive-first or stdin-only — the wrapper is
  documented in each YAML's description and a separate Cycle 3
  ticket lands the actual scripts in the image.
* The ten direct-targeting tools consume `{url}`; `sqlmap_safe`
  additionally consumes `{safe}` (the throttle endpoint sqlmap
  hits between probes to avoid lockout); `playwright_xss_verify`
  additionally consumes `{canary}` to fire the operator-supplied
  marker. Pinned by per-tool semantic tests.
* Every `description` carries the upstream author + canonical source
  URL and tags `Backlog/dev1_md §4.9` or `§4.10` so
  `python -m scripts.docs_tool_catalog` renders provenance into
  `docs/tool-catalog.md`.

### Parsers (`backend/src/sandbox/parsers/`)

#### `sqlmap_parser.py` (688 lines)

Single strict-typed module exporting one public callable plus the
`EVIDENCE_SIDECAR_NAME` constant:

| Symbol                | Tool ID(s)                          | Notes                                                                                                                                                                                                                                                                                                              |
| --------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `parse_sqlmap_output` | `sqlmap_safe`, `sqlmap_confirm`     | Text-line parser for `sqlmap`'s structured stdout / log files. Resolves canonical `{out_dir}/sqlmap[_confirm]/log/*.log` first (sqlmap writes per-host log files), falls back to stdout when no log artefact is found. One `FindingDTO` per `(target_url, parameter_name, location)` regardless of techniques.    |

Per-record extraction (sqlmap):

| Source line                                       | Result                                                                                                       |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `Parameter: <name> (<location>)`                  | Drives `(param, location)` half of the dedup key.                                                            |
| `Type: <technique>`                               | Folded into the evidence `techniques[]` array (boolean-based blind / time-based blind / UNION / error-based / stacked-queries). |
| `Title: <description>`                            | Folded into the evidence `titles[]` array — preserves sqlmap's per-technique English descriptions.           |
| `Payload: <payload>`                              | Folded into the evidence `payloads[]` array — truncated to 4 KiB per payload (defence-in-depth against pathological URL parameters). |
| `[INFO] testing URL '<url>'` / `target URL: ...` | Drives `target_url` field — multiple URLs in the same log split into multiple findings.                       |
| `back-end DBMS: <dbms>`                           | Folded into the evidence `dbms` field (e.g. `MySQL >= 5.0.12`, `PostgreSQL 11.2`).                            |
| Lines outside the `Parameter:` block              | Captured into a 4 KiB log excerpt for triage (truncated UTF-8 safe).                                          |

Shared invariants:

* Severity is preserved through the CVSS sentinel
  (`cvss_v3_score=0.0`, `cvss_v3_vector=SENTINEL_CVSS_VECTOR`,
  `id=SENTINEL_UUID`). The downstream `Normalizer` lifts the score
  using the SQLi taxonomy (typically CVSS 3.1 / AV:N AC:L PR:N UI:N
  S:U C:H I:H A:H = 9.8) once the sentinel is resolved.
* Confidence pinned to `CONFIRMED` — sqlmap only emits a `Parameter:`
  block after it has actually exploited the injection (boolean,
  time-based, etc.); detection without exploitation never reaches
  this state.
* Category pinned to `FindingCategory.SQLI`; CWE pinned to `[89]`
  (CWE-89 SQL Injection); OWASP WSTG pinned to `["WSTG-INPV-05"]`.
* Evidence sidecar: every parser run writes a single
  `{artifacts_dir}/sqlmap_findings.jsonl` JSON-Lines file (one record
  per finding, `tool_id` stamped per line). Both `sqlmap_safe` and
  `sqlmap_confirm` share the same sidecar name and rely on the
  `tool_id` field to demultiplex downstream.
* Hard cap: **5 000** unique findings per run — protects the worker
  from a permissive `--level 5 --risk 3` sqlmap run that scales
  linearly with target parameter count. Subsequent records are
  dropped silently (logged via `_logger`, never raised).
* Records collapse on a stable `(target_url, param, location)` key —
  every sub-technique (boolean+time+error+UNION) folds into one
  finding while the per-technique evidence (`techniques`, `titles`,
  `payloads`) is preserved inside the sidecar.
* Output ordering is deterministic — sorted by the dedup key so a
  re-run of sqlmap against the same site yields the same finding
  sequence regardless of the order sqlmap itself reports them.
* Sidecar I/O failures are swallowed (logged as `WARNING`, never
  raised) — the parser's contract is "best-effort evidence
  persistence".
* Module-top imports only, no `subprocess`, no real network, no
  `os.environ` reads. Reuses the existing `safe_decode` helper from
  `src.sandbox.parsers._base` so a malformed UTF-8 stream returns
  `[]` after structured `WARNING` logs, never raises.
* Path-traversal segments in the canonical artifact glob are refused
  by `_read_log_files` (any `..` or absolute path short-circuits to
  the stdout fallback).

#### `dalfox_parser.py` (538 lines)

Single strict-typed module exporting one public callable plus the
`EVIDENCE_SIDECAR_NAME` constant:

| Symbol              | Tool ID(s) | Notes                                                                                                                                                                                                                                                                                                                                                       |
| ------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `parse_dalfox_json` | `dalfox`   | JSON-envelope parser for `dalfox`'s `--format json` output. Resolves canonical `{out_dir}/dalfox.json` first, falls back to stdout when the canonical artefact is absent. One `FindingDTO` per `(url, method, param, payload[:200])` after dedup.                                                                                                            |

Per-record classification (dalfox):

| Source field          | Result                                                                                                                            |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `type`                | Drives `(category, confidence)` per the `_TYPE_MAP` table: `V` → `(XSS, CONFIRMED)`, `S` → `(XSS, LIKELY)`, `R` → `(INFO, SUSPECTED)`. Unknown types fall back to `(INFO, SUSPECTED)`. |
| `severity`            | Drives the dedup-key tie-breaker so high-severity records survive the cap when many low-severity duplicates exist.                |
| `cwe`                 | Both `"CWE-79"` (string) and `["CWE-79", 80]` (list with mixed shapes) tolerated; CWE tokens normalised (`CWE-79`, `79`, `cwe-79` all → `79`); booleans + negative integers rejected. Defaults to `[79]` when absent. |
| `url` / `method` / `param` / `payload` | Drive the dedup key + populate the evidence sidecar.                                                                     |
| `evidence` / `poc` / `tag` / `category` | Captured verbatim into the evidence sidecar (UTF-8 safe-truncated to 4 KiB each).                                       |

Shared invariants:

* Severity is preserved through the CVSS sentinel (same as
  `sqlmap_parser`); the Normalizer lifts it once the per-CVE / per-tag
  enrichment runs.
* Three-tier confidence ladder: `V` (Verified) → `CONFIRMED`,
  `S` (Stored) → `LIKELY`, `R` (Reflected) → `SUSPECTED`. The
  category pinning reflects whether the finding is exploitable
  (V/S → `XSS`) vs. observation-only (R → `INFO`).
* Evidence sidecar: every parser run writes a single
  `{artifacts_dir}/dalfox_findings.jsonl` JSON-Lines file.
* Hard cap: **5 000** unique findings per run.
* Records collapse on a stable `(url, method, param, payload[:200])`
  key — the payload prefix bounds the dedup key to 200 chars to
  prevent payload-mutation noise from blowing up the dedup index.
* Output ordering is deterministic — sorted by `(-severity_rank, url,
  param, payload[:200])` so a re-run of dalfox yields the same
  finding sequence and high-severity findings always sort first.
* Three input shapes accepted: bare list `[{...}, ...]`, wrapped
  envelope `{"results": [...]}`, and single-record `{...}`.
  Anything else returns `[]` after a structured `WARNING`.
* Same fail-soft / no-network / no-env contracts as
  `sqlmap_parser.py`.

### Parser dispatch (`backend/src/sandbox/parsers/__init__.py`)

```python
"sqlmap_safe":     parse_sqlmap_output,
"sqlmap_confirm":  parse_sqlmap_output,
"dalfox":          parse_dalfox_json,
```

Plus the new `ParseStrategy.TEXT_LINES` strategy handler is
registered through `_build_default_strategy_handlers` (sqlmap is the
first tool to use it).

The eight `parse_strategy: text_lines` / `json_object` tools without
a per-tool parser entry (`ghauri`, `tplmap`, `nosqlmap`, `kxss`,
`jsql`, `xsstrike`, `xsser`, `playwright_xss_verify`) intentionally
fall through to the generic strategy handler (which logs an
`unmapped_tool` warning and returns `[]` until a dedicated parser
ships in Cycle 3). The downstream pipeline tolerates this — the raw
evidence file is still preserved per each YAML's
`evidence_artifacts` block.

The integration test
`tests/integration/sandbox/parsers/test_dispatch_registry.py::test_reset_registry_restores_default_handlers`
was updated to include `ParseStrategy.TEXT_LINES` in the canonical
default-strategies frozenset; this pins the new strategy in the
default registry so a future refactor catches accidental removal.

### Tests (`backend/tests/...`)

| File                                                                 | Tests | What it covers                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------------------------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unit/sandbox/parsers/test_sqlmap_parser.py`                         | 23    | Log-precedence (canonical glob → stdout fallback), parameter / type / payload / DBMS extraction, multi-host directory walking, multi-technique folding, deduplication, deterministic sorting, hard cap at 5 000 findings, evidence sidecar contract (`tool_id` stamping), best-effort sidecar I/O failure handling, malformed line skip, payload truncation, canonical-glob path-traversal block. |
| `unit/sandbox/parsers/test_dalfox_parser.py`                         | 31    | Canonical artefact precedence, stdout fallback, V/S/R → category/confidence ladder, CWE normalization (string + list + integer + boolean rejection + negative-integer rejection), deduplication, deterministic ordering, hard cap, payload truncation, three input-envelope shapes (list / wrapped / single), `tool_id` stamping, sidecar contract, fail-soft on malformed JSON.        |
| `unit/sandbox/test_yaml_sqli_semantics.py`                           | 102   | Per-tool taxonomy invariants for all 6 §4.9 SQLi YAMLs (image, network policy, parse strategy split, CWE hints per tool with `tplmap` SSTI exception, OWASP `WSTG-INPV-*` family, timeouts, resource limits, argv shell-metachar audit, binary name pin, description provenance + length, URL placeholder consumption, `sqlmap_safe` `--technique=BT` + `--safe-url` invariants).         |
| `unit/sandbox/test_yaml_xss_semantics.py`                            | 107   | Per-tool taxonomy invariants for all 5 §4.10 XSS YAMLs (image distribution including `playwright_xss_verify` browser image, phase split, no-approval-required for the entire batch, parse strategy distribution, timeouts, resource limits, argv shell-metachar audit, description provenance, URL placeholder consumption, `playwright_xss_verify` canary + screenshot output pins, `kxss` runner-script pin). |
| `integration/sandbox/test_arg016_end_to_end.py`                      | 22    | End-to-end vertical slice: builds an isolated tool catalog under `tmp_path` containing only the eleven §4.9/§4.10 YAMLs (plus a fresh dev signing key), loads it through `ToolRegistry`, renders every `command_template` cleanly with sandbox-internal placeholders, dispatches synthetic sqlmap log + dalfox JSON through `dispatch_parse`, asserts findings + sidecar shape + V/S/R ladder + canonical-artifact preference. |
| `integration/sandbox/parsers/test_dispatch_registry.py` (extended)   | n/a   | `test_reset_registry_restores_default_handlers` extended to include `ParseStrategy.TEXT_LINES` in the canonical default-strategies set.                                                                                                                                                                                                                                                |
| `integration/sandbox/test_tool_catalog_load.py` (extended)           | n/a   | Adds `SQLI_TOOLS` (6 ids) + `XSS_TOOLS` (5 ids) + `SQLI_APPROVAL_REQUIRED` (5 ids) + `_EXPLOITATION_PHASE_TOOLS` (2 ids) frozensets to the canonical inventory; raises the global lower bound from `>= 77` to `== 88`; refactored `test_descriptor_approval_matches_risk_profile` to combine §4.8 + §4.9 approval-gated tools; added `test_sqli_tools_*` + `test_xss_tools_*` dedicated invariant suites. |
| `unit/sandbox/test_yaml_schema_per_tool.py` (extended)               | n/a   | Pydantic schema parse, placeholder allow-list, image namespace, timeout bounds for every §4.9/§4.10 YAML; `EXPECTED_TOOL_IDS` and `test_expected_count_matches_current_scope` updated to **88**.                                                                                                                                                                                       |

Coverage delta on the new parsers:

```
Name                                   Stmts   Miss  Cover
----------------------------------------------------------
src\sandbox\parsers\dalfox_parser.py     183      5    97%
src\sandbox\parsers\sqlmap_parser.py     245     16    93%
----------------------------------------------------------
TOTAL                                    428     21    95%
```

Both parsers comfortably clear the 90 % acceptance gate. The
remaining uncovered branches are best-effort `OSError` handlers on
sidecar writes and defensive guards against malformed
`safe_decode` returns that the integration suite would exercise
through real disk I/O if it ran with end-to-end coverage enabled.

### Tool catalog (`docs/tool-catalog.md`)

Re-rendered via `python -m scripts.docs_tool_catalog --check`:

```
docs_tool_catalog.check_ok tools=88 path=D:\Developer\Pentest_test\ARGUS\docs\tool-catalog.md
```

`scripts/docs_tool_catalog.py` updated:

* `_EXPECTED_TOOLS_PER_PHASE` → `recon: 46`, `vuln_analysis: 40`,
  `exploitation: 2` (the §4.10 `playwright_xss_verify` + the §4.9
  `sqlmap_confirm` are the first two `exploitation`-phase tools to
  land in the catalog).
* Header references **ARG-001..ARG-016** and `§4.9 / §4.10`.
* Coverage-matrix description extended to call out the 11-tool
  ARG-016 batch.

Per-phase totals after this batch:

* `recon`: unchanged (46 tools — no §4.9/§4.10 additions).
* `vuln_analysis`: 31 → **40** tools (+9 from §4.9 SQLi minus
  `sqlmap_confirm` + §4.10 XSS minus `playwright_xss_verify`).
* `exploitation`: 0 → **2** tools (+`sqlmap_confirm`,
  +`playwright_xss_verify`).

### Catalog signing (`backend/config/tools/SIGNATURES`)

```powershell
$ python scripts/tools_sign.py verify --tools-dir config/tools `
    --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
verify_ok signatures=88 keys=11
```

All 88 YAMLs (11 ARG-016 + 7 ARG-015 + 70 prior) re-signed under
key id `716d97706bc708e2` (Ed25519, 32-byte raw public key in
`_keys/716d97706bc708e2.ed25519.pub`). The audit trail of historical
public keys is preserved (11 `.pub` files in `_keys/`); the matching
private key was deleted after signing per the `_keys/README.md`
workflow ("generate, sign, verify, then delete").

---

## Acceptance gate

```powershell
$ python scripts/tools_sign.py verify --tools-dir config/tools `
    --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
verify_ok signatures=88 keys=11

$ python -m pytest tests/unit/sandbox tests/integration/sandbox `
    tests/test_tool_catalog_coverage.py
2898 passed in 77.18s

$ python -m pytest tests/unit/sandbox/parsers/test_sqlmap_parser.py `
    tests/unit/sandbox/parsers/test_dalfox_parser.py `
    --cov=src.sandbox.parsers.sqlmap_parser `
    --cov=src.sandbox.parsers.dalfox_parser --cov-report=term-missing
54 passed in 4.43s
TOTAL                                    428     21    95%

$ python -m pytest tests/integration/sandbox/test_arg016_end_to_end.py -v
22 passed in 2.20s

$ python -m mypy src/sandbox/parsers/sqlmap_parser.py `
    src/sandbox/parsers/dalfox_parser.py src/sandbox/parsers/__init__.py
Success: no issues found in 3 source files

$ python -m ruff check src/sandbox/parsers/sqlmap_parser.py `
    src/sandbox/parsers/dalfox_parser.py src/sandbox/parsers/__init__.py `
    tests/unit/sandbox/parsers/test_sqlmap_parser.py `
    tests/unit/sandbox/parsers/test_dalfox_parser.py `
    tests/integration/sandbox/test_arg016_end_to_end.py `
    tests/unit/sandbox/test_yaml_sqli_semantics.py `
    tests/unit/sandbox/test_yaml_xss_semantics.py `
    tests/integration/sandbox/test_tool_catalog_load.py `
    tests/unit/sandbox/test_yaml_schema_per_tool.py `
    scripts/docs_tool_catalog.py
All checks passed!

$ python -m ruff format --check src/sandbox/parsers tests/unit/sandbox `
    tests/integration/sandbox scripts/docs_tool_catalog.py
All checks passed!

$ $env:PYTHONPATH = "."; python scripts/docs_tool_catalog.py --check
docs_tool_catalog.check_ok tools=88 path=D:\Developer\Pentest_test\ARGUS\docs\tool-catalog.md
```

All ACs from the cycle plan satisfied:

1. ✅ `tools_list --json | jq length` → **88** (registry verified
   load-time at startup; `RegistrySummary.total == 88`).
2. ✅ Coverage gate: 88 × 5 = **440** parametrised cases; green
   (`tests/test_tool_catalog_coverage.py` — 440 passed).
3. ✅ `sqlmap_confirm` YAML carries `requires_approval: true`;
   pinned by `test_sqli_descriptors_carry_correct_phase_and_image`
   in `test_arg016_end_to_end.py` AND by
   `test_descriptor_approval_matches_risk_profile` in
   `test_tool_catalog_load.py`.
4. ✅ `playwright_xss_verify` uses `argus-kali-browser:latest`;
   pinned by `test_xss_descriptors_carry_correct_phase_and_image`
   AND by `test_xss_tools_image_distribution` in the integration
   suite.
5. ✅ `pytest -q tests/unit/sandbox/parsers/test_sqlmap_parser.py
   tests/unit/sandbox/parsers/test_dalfox_parser.py
   tests/integration/sandbox tests/test_tool_catalog_coverage.py`
   — 2 898 passed.
6. ✅ `python -m scripts.docs_tool_catalog --check` — in sync.
7. ✅ Parser coverage **95 %** combined (well above the 90 %
   acceptance gate; dalfox 97 %, sqlmap 93 %).

---

## Risks / out-of-scope

* **`playwright_xss_verify` runner script** (`/usr/local/bin/playwright-verify-xss`)
  — **deferred to Cycle 3 ARG-019**. The YAML lands the
  `command_template` and image pin so the dispatch flow renders
  cleanly, but the actual Node wrapper that loads the URL with the
  canary marker, captures DOM execution, and writes the verdict JSON
  will land alongside the rest of the browser-based supply chain
  (Playwright + Chromium) in `sandbox/scripts/playwright/`.
* **`xsstrike` / `xsser` / `kxss` / `jsql`** — deferred parsers. These
  ship with their `parse_strategy` set (per the YAML) but **no**
  per-tool dispatch entry in `_DEFAULT_TOOL_PARSERS`; the worker
  writes the raw evidence file (`xsstrike.json`, `xsser.json`,
  `kxss.txt`, `jsql.json`) but emits zero `FindingDTO`s in this
  cycle. Cycle 3 will add per-tool parsers for each format
  (`xsstrike` and `xsser` JSON envelopes are stable; `kxss` is
  one-line-per-finding text; `jsql` is a Java-side report we'll
  wrap with a thin transformer).
* **`tplmap` / `nosqlmap`** — deferred parsers (text output, no
  per-tool dispatch entry). Cycle 3 will add a `tplmap_text` parser
  (single-finding extraction from `--os-cmd` confirmation lines) and
  a `nosqlmap_text` parser (per-payload extraction from the
  attack-profile-2 banner format).
* **`ghauri`** — deferred parser. The image-side wrapper writes
  verbose stdout into `/out/ghauri.log`; Cycle 3 will mirror the
  `sqlmap_parser.py` text-lines pattern against the ghauri log
  format (different field names but identical structure).
* **`recon-active-tcp` `NetworkPolicy`** is reused for all eleven
  §4.9/§4.10 tools — the existing template already enforces the
  right egress (target CIDR only, DNS pinned), so adding a parallel
  `web-injection` policy would have been pure churn. The semantic
  tests pin the choice
  (`test_sqli_tools_use_recon_active_tcp_policy`,
  `test_xss_tools_use_recon_active_tcp_policy`) so a future
  refactor catches the assumption.
* **`sqlmap_confirm`'s `--technique=E` + `--dbs --count`** is the
  most aggressive profile in the entire ARGUS catalog — it actively
  exploits a confirmed SQLi to dump schema and will trigger WAF /
  IDS alerts at the target. The `requires_approval: true` gate is
  the only safety rail; the `recon-active-tcp` policy + the
  `argus-kali-web` image's seccomp profile prevent post-exploitation
  side effects but they cannot prevent the per-host blast radius.
  Operators **must** review the approval prompt before kicking off
  this tool.
* **`tplmap`'s `--os-cmd id`** is a real RCE attempt against a
  confirmed template-injection engine. The `requires_approval: true`
  + `risk_level: high` combo gates this behind the same operator
  review as `sqlmap_confirm`.
* **The `validation` phase** missing in the `ScanPhase` enum is a
  Cycle 1 design gap. ARG-016 maps `playwright_xss_verify` onto
  `exploitation` + `risk_level: low` (which keeps approval off), but
  this is a workaround — Cycle 3 should land a proper `validation`
  enum value and migrate `playwright_xss_verify` to it. The YAML
  description documents the mapping so a future refactor doesn't
  silently break the contract.
* **Pre-existing broken signatures in `payloads/SIGNATURES` and
  `prompts/SIGNATURES`** — surface as `PayloadSignatureError` /
  `PromptSignatureError` in 144 tests under
  `tests/integration/payloads/`, `tests/integration/policy/`,
  `tests/integration/oast/`, `tests/integration/orchestrator_runtime/`.
  These are **out of scope** for ARG-016 (different subsystems;
  separate signing realms — `src.payloads` and
  `src.orchestrator.prompt_registry`). The 88-tool catalog signing
  workflow this batch ran does not touch those files.

---

## Files touched

```
NEW   backend/config/tools/sqlmap_safe.yaml
NEW   backend/config/tools/sqlmap_confirm.yaml
NEW   backend/config/tools/ghauri.yaml
NEW   backend/config/tools/jsql.yaml
NEW   backend/config/tools/tplmap.yaml
NEW   backend/config/tools/nosqlmap.yaml
NEW   backend/config/tools/dalfox.yaml
NEW   backend/config/tools/xsstrike.yaml
NEW   backend/config/tools/kxss.yaml
NEW   backend/config/tools/xsser.yaml
NEW   backend/config/tools/playwright_xss_verify.yaml
NEW   backend/config/tools/_keys/716d97706bc708e2.ed25519.pub
MOD   backend/config/tools/SIGNATURES                         (re-signed all 88 entries under the new key)
NEW   backend/src/sandbox/parsers/sqlmap_parser.py            (688 lines, 93 % line coverage)
NEW   backend/src/sandbox/parsers/dalfox_parser.py            (538 lines, 97 % line coverage)
MOD   backend/src/sandbox/parsers/__init__.py                 (TEXT_LINES handler registration + sqlmap/dalfox dispatch entries)
NEW   backend/tests/unit/sandbox/parsers/test_sqlmap_parser.py
NEW   backend/tests/unit/sandbox/parsers/test_dalfox_parser.py
NEW   backend/tests/unit/sandbox/test_yaml_sqli_semantics.py
NEW   backend/tests/unit/sandbox/test_yaml_xss_semantics.py
NEW   backend/tests/integration/sandbox/test_arg016_end_to_end.py
MOD   backend/tests/integration/sandbox/test_tool_catalog_load.py
MOD   backend/tests/integration/sandbox/parsers/test_dispatch_registry.py
MOD   backend/tests/unit/sandbox/test_yaml_schema_per_tool.py
MOD   backend/scripts/docs_tool_catalog.py                    (per-phase counts updated; ARG-016 / §4.9-10 references)
MOD   docs/tool-catalog.md                                    (regenerated from the registry — 88 tools)
MOD   backend/src/api/routers/findings.py                     (drop legacy "HexStrike v4" docstring → ARGUS v4)
MOD   backend/src/api/routers/intelligence.py                 (drop legacy "HexStrike v4" docstring → ARGUS v4)
MOD   backend/src/api/routers/sandbox.py                      (drop legacy "HexStrike v4" docstring → ARGUS v4)
MOD   backend/src/api/routers/scans.py                        (drop legacy "HexStrike v4" docstrings ×2 → ARGUS v4)
MOD   backend/src/api/schemas.py                              (drop legacy "HexStrike v4" docstring → ARGUS v4)
```

> **Hexstrike legacy gate addendum (post-verification):** The
> `tests/test_argus006_hexstrike.py` grep-style hygiene gate
> required by the ARG-016 prompt was failing on the `main` worktree
> against six pre-existing docstrings in `backend/src/api/`
> (originally introduced by the `f11447b feat(hexstrike-v4)` commit
> and never purged in ARG-015). Replaced "HexStrike v4" → "ARGUS v4"
> in those six lines (5 files, +6 / -6 chars per line, no behaviour
> change). The legacy gate now passes (`1 passed in 6.43s`) and the
> sandbox + parser + tool-catalog suites stay at the same green count.

---

## Telemetry

* Strategy registry (`get_registered_strategies()`) post-load:
  `{JSON_LINES, JSON_OBJECT, NUCLEI_JSONL, TEXT_LINES}` — 1 new
  strategy delivered (TEXT_LINES).
* Tool registry (`ToolRegistry.load() → RegistrySummary.by_phase`)
  post-load: `{recon: 46, vuln_analysis: 40, exploitation: 2}` —
  Cycle 2 reaches the §4.9/§4.10 milestone.
* Per-tool parser dispatch (`get_registered_tool_parsers()`) post-load:
  17 entries (14 prior + `sqlmap_safe`, `sqlmap_confirm`, `dalfox`).
* Sandbox suite size: 2 685 (post-ARG-015) → **2 898** tests
  (post-ARG-016) — 213 new tests delivered against the 90 % parser
  coverage gate, 88-tool catalog inventory, and ARG-016 e2e slice.

---

## Next batch hand-off

* Cycle 2 §4.11 SSRF/OAST + §4.12 Auth/brute + §4.13 Hash (ARG-017)
  picks up the next 20 tools and the `interactsh_jsonl` parser.
  ARG-017 inherits ARG-016's text-line strategy infrastructure for
  `interactsh_client` (which produces a JSONL stream similar to
  nuclei but with OAST callback semantics).
* Cycle 3 should land:
  * `playwright_xss_verify` Node wrapper script.
  * `xsstrike_json`, `xsser_json`, `kxss_text`, `jsql_json`
    parsers (one ticket per format).
  * `tplmap_text`, `nosqlmap_text`, `ghauri_text` parsers
    (text-line pattern, mirror `sqlmap_parser.py`).
  * `validation` phase added to the `ScanPhase` enum + migrate
    `playwright_xss_verify` off the `exploitation` workaround.
* The flagship `parse_sqlmap_output` parser handles the **stable**
  sqlmap log format (1.7.x). If sqlmap upstream changes the
  `Parameter:` / `Type:` / `Payload:` block layout, the parser logs
  an `unknown_record_shape` warning and skips the record rather than
  crashing — but the regex set will need an update. The unit suite
  includes 6 targeted shape-mutation tests (indented vs. unindented
  blocks, missing `Title:` lines, missing `Payload:` line, multi-host
  log directories) that the integration team can extend when sqlmap
  ships breaking changes.
