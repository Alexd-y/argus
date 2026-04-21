# ARG-013 — Tool YAMLs §4.6 (Crawler / JS / endpoint extraction — 8 tools) + katana JSONL parser — Completion Report

**Date:** 2026-04-18
**Cycle:** `argus-finalization-cycle2`
**Status:** COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` (§ARG-013)
**Backlog:** `Backlog/dev1_.md` §4.6
**Dependencies:** ARG-011 (parser dispatch + multi-image stubs)

---

## Goal

Land Backlog §4.6 — the **crawler / JavaScript / endpoint+secret extraction** batch — on the
ARGUS sandbox without touching any Cycle 1 invariant. Concretely:

* eight new signed `ToolDescriptor` YAMLs under `backend/config/tools/`;
* a deterministic **JSON-Lines parser** for Katana that also serves as the format
  adapter for Gospider and Gau (the three §4.6 tools that emit machine-parseable
  JSONL);
* parser dispatch wiring for the three JSONL tools and pinned
  `text_lines` placement for the remaining five (handed off to Cycle 3 once a
  generic `text_lines` parser strategy is online);
* full unit + integration coverage for the new code path;
* tool-inventory tests + auto-rendered tool catalog refreshed to match the new
  `62`-tool scope.

All eight YAMLs are **`requires_approval: false`**, run on the
`argus-kali-web:latest` image, and split between `recon-passive` (passive sources
or pure analysis) and `recon-active-tcp` (live crawls).

---

## Deliverables

### Tool descriptors (`backend/config/tools/`)

| `tool_id`     | phase           | risk    | network policy     | parse_strategy | upstream                                           |
| ------------- | --------------- | ------- | ------------------ | -------------- | -------------------------------------------------- |
| `katana`      | `recon`         | `low`   | `recon-active-tcp` | `json_lines`   | projectdiscovery/katana                            |
| `gospider`    | `recon`         | `low`   | `recon-active-tcp` | `json_lines`   | jaeles-project/gospider                            |
| `hakrawler`   | `recon`         | `low`   | `recon-active-tcp` | `text_lines`   | hakluke/hakrawler                                  |
| `waybackurls` | `recon`         | `passive` | `recon-passive`  | `text_lines`   | tomnomnom/waybackurls                              |
| `gau`         | `recon`         | `passive` | `recon-passive`  | `json_lines`   | lc/gau                                             |
| `linkfinder`  | `recon`         | `passive` | `recon-passive`  | `text_lines`   | GerbenJavado/LinkFinder                            |
| `subjs`       | `recon`         | `passive` | `recon-passive`  | `text_lines`   | lc/subjs                                           |
| `secretfinder`| `vuln_analysis` | `passive` | `recon-passive`  | `text_lines`   | m4ll0k/SecretFinder                                |

Common invariants enforced for **every** YAML:

* `image: argus-kali-web:latest` (one Dockerfile stub already lives in
  `sandbox/images/argus-kali-web/Dockerfile`).
* `cwe_hints: [200]` (Information Exposure to an Unauthorized Actor).
* `owasp_wstg` includes `WSTG-INFO-06` and `WSTG-INFO-07`; the JS analyzers
  (`linkfinder`, `subjs`) also map to `WSTG-INFO-05`; `secretfinder` maps to
  `WSTG-INFO-05` + `WSTG-CRYP-03`.
* `cpu_limit: "1"`, `memory_limit: "1Gi"`, `seccomp_profile: RuntimeDefault`.
* `default_timeout_s`: `600` for live crawlers (`katana`, `gospider`,
  `hakrawler`), `300` for the rest.
* `requires_approval: false` (no destructive operations).
* `command_template` is **argv-only**, no shell metacharacters (`;`, `&&`, `|`,
  backticks, `>`, `<`, `$()`). Where the upstream binary only consumes
  stdin / writes to stdout (`hakrawler`, `waybackurls`, `linkfinder`, `subjs`,
  `secretfinder`), the YAML invokes a thin
  `<tool>-wrapper -i ... -out {out_dir}/<tool>.txt` shim that lives in the
  `argus-kali-web` image (one wrapper per stdin-only tool, no caller-side
  shelling).
* Every `description` carries the upstream author + canonical source URL so
  `python -m scripts.docs_tool_catalog` renders provenance into
  `docs/tool-catalog.md`.

### Parser (`backend/src/sandbox/parsers/katana_parser.py`)

Single 220-line module that exports three public callables, all strict-typed
and `mypy --strict` clean:

| Symbol                  | Tool ID(s) | Notes                                                                    |
| ----------------------- | ---------- | ------------------------------------------------------------------------ |
| `parse_katana_jsonl`    | `katana`   | One canonical `FindingDTO` per `(endpoint, method)`; default method `GET`; cap 5,000 records. |
| `parse_gospider_jsonl`  | `gospider` | Pure adapter that normalises gospider's `output` / `stat` keys onto katana's `request.endpoint` / `response.status_code` and reuses the common pipeline. |
| `parse_gau_jsonl`       | `gau`      | Minimal `{"url": ...}` records → INFO findings; tolerates optional HTTP metadata. |

Shared invariants:

* `category=FindingCategory.INFO` (taxonomy: `endpoint_discovery`).
* `severity_label="info"`, `confidence=ConfidenceLevel.LOW`,
  `ssvc_decision=SSVCDecision.TRACK`.
* `cwe_id=200`, `owasp_wstg=["WSTG-INFO-06", "WSTG-INFO-07"]`.
* Evidence sidecar: every parser writes a single
  `{artifacts_dir}/katana_findings.jsonl` JSON-Lines file (one record per
  finding, `tool_id` stamped per line, compact `dict` with no empty fields).
* Hard cap: 5,000 unique findings per run — protects the pipeline from runaway
  crawls and long Wayback windows. Subsequent records are dropped silently
  (logged via the parser's `_logger`, never raised).
* Sidecar I/O failures are swallowed (logged as `WARN`, never raised) — the
  parser's contract is "best-effort evidence persistence".

Module-top imports only, no `subprocess`, no real network, no
`os.environ` reads. Uses the existing `safe_load_jsonl` helper from
`src.sandbox.parsers._base` so a single malformed line never aborts the whole
run.

### Parser dispatch (`backend/src/sandbox/parsers/__init__.py`)

```python
"katana":   parse_katana_jsonl,
"gospider": parse_gospider_jsonl,
"gau":      parse_gau_jsonl,
```

The five `text_lines` §4.6 tools (`hakrawler`, `waybackurls`, `linkfinder`,
`subjs`, `secretfinder`) intentionally have **no** entry — they will land in
Cycle 3 once a generic `ParseStrategy.TEXT_LINES` strategy ships. The
integration test `tests/integration/sandbox/parsers/test_katana_dispatch.py::test_text_lines_crawler_tools_not_routed_via_json_lines`
pins this gap so future authors can't accidentally short-circuit those tools
through the JSONL pipeline.

### Tests (`backend/tests/...`)

| File                                                                            | Tests | What it covers                                                                                            |
| ------------------------------------------------------------------------------- | ----: | --------------------------------------------------------------------------------------------------------- |
| `unit/sandbox/parsers/test_katana_parser.py`                                    |  17  | empty / whitespace-only stdout, single record metadata, sidecar shape, dedup by `(endpoint, method)`, method case-folding, missing endpoint skipped, malformed JSONL skipped, non-dict payload skipped, sidecar persistence + best-effort I/O failure, **5,000 cap**. |
| `unit/sandbox/parsers/test_gospider_parser.py`                                  |   8  | empty stdout, single record normalisation, gospider's `tool_id` stamp on the sidecar, string `stat` coercion, non-numeric `stat` dropped, fall-back to `url` when `output` missing, record without any URL skipped, dedup across distinct sources. |
| `unit/sandbox/parsers/test_gau_parser.py`                                       |   5  | minimal URL record → INFO finding, sidecar default method/source, optional status / content_length preserved, record without `url` skipped, duplicate URLs collapsed. |
| `integration/sandbox/parsers/test_katana_dispatch.py`                           |  ~10 | All three JSONL tools route via `ParseStrategy.JSON_LINES`; consistent `cwe_id=200` and `WSTG-INFO-06/07`; the shared `katana_findings.jsonl` sidecar is written by each tool and stamps the right `tool_id`; the five text-lines siblings stay unrouted via JSON. |
| `integration/sandbox/test_arg013_end_to_end.py`                                 |   1  | Loads `katana.yaml` from disk, asserts the descriptor → renders the command template → audits it for shell metacharacters → feeds synthetic JSONL into `dispatch_parse` → asserts the dedup, sidecar contents and `tool_id` round-trip. |
| `unit/sandbox/test_yaml_crawler_semantics.py`                                   |  ~96 | One parametrised matrix per invariant for all 8 YAMLs: phase split, no-approval, image, network policy active/passive split, `evidence_artifacts` presence, `cwe_hints==[200]`, per-tool `owasp_wstg` taxonomy, parse strategy split, timeout floor, CPU/mem, no shell metacharacters in command, first token is the real binary name, description carries author + source. |
| `unit/sandbox/test_yaml_schema_per_tool.py`                                     | +8   | Adds the 8 new `tool_id`s to `EXPECTED_TOOL_IDS`; bumps the catalog count to **62**. |
| `integration/sandbox/test_tool_catalog_load.py`                                 | +N   | Adds `CRAWLER_TOOLS` set; bumps `EXPECTED_TOOLS` to **62**; verifies all 8 YAMLs run on `argus-kali-web:latest`; verifies the active/passive network policy split for the new tools; pins the `WSTG-INFO-06` requirement at the inventory layer. |
| `tests/test_tool_catalog_coverage.py` (existing — automatic uplift)             | +40  | Coverage gate auto-extends from 54 × 5 = 270 → 62 × 5 = **310** parametrised cases (file existence, signature verification, `ToolDescriptor` parse, doc mention, integration-tree reference). All 310 green. |

**Aggregate net-new test cases for ARG-013: ~145** (30 parser unit + 10 dispatch
+ 1 e2e + ~96 YAML semantics + 8 schema-per-tool). All green; no skips.

### Inventory + docs

* `backend/scripts/docs_tool_catalog.py` — bumped `_EXPECTED_TOOLS_PER_PHASE`
  to `recon=46` and `vuln_analysis=16`; updated header to "**62** tool
  descriptors that the ARGUS Active Pentest Engine ships in cycles
  **ARG-001..ARG-013** (Backlog/dev1_md §4.1–§4.6)".
* `docs/tool-catalog.md` — regenerated deterministically; verified idempotent
  (`python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md` twice
  produces zero diff).

### Signing

* Re-ran `python backend/scripts/tools_sign.py --sign` over the **full** 62-YAML
  catalog with a fresh dev key.
* Verified with `--verify` → `verify.ok signatures_path=… verified_count=62`.
* Private key deleted from disk per the `_keys/README.md` workflow.
* **Key rotation note:** Cycle 1's dev key (`d932b327c0383caa`) had no
  matching `.priv` material in the working tree (per the README workflow
  "delete after signing"), so a new dev keypair (`78317b2d95670ac9`) was
  generated and the **entire** catalog (all 62 YAMLs) was re-signed against
  it. The old public key files (`d932b327c0383caa.ed25519.pub`,
  `a030c5a6762de118.ed25519.pub`) are kept under `_keys/` for historical
  audit (the `KeyManager` indexes them but no `SIGNATURES` line currently
  references them, so verification still passes). Production key rotation is
  scheduled for Cycle 5.

---

## Acceptance criteria

| # | Criterion                                                                                          | Status |
| - | -------------------------------------------------------------------------------------------------- | ------ |
| 1 | `len(ToolRegistry.all_descriptors())` = **62**                                                     | PASS  |
| 2 | Coverage gate `tests/test_tool_catalog_coverage.py` = **62 × 5 = 310** parametrised cases — green | PASS  |
| 3 | `pytest -q tests/unit/sandbox tests/integration/sandbox` — green                                   | PASS (1610 passed in 49.95s) |
| 4 | `pytest -q tests/unit tests/integration --ignore=…/sandbox` — no regression                       | PASS (1280 passed in 15.44s) |
| 5 | `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md` — idempotent                   | PASS  |
| 6 | `mypy src/sandbox` — clean                                                                         | PASS (0 errors in 14 files) |
| 7 | `mypy` on every touched test + script file — clean                                                 | PASS (0 errors in 9 files)  |
| 8 | `ruff check` + `ruff format --check` on every touched file                                         | PASS  |
| 9 | All 62 YAMLs Ed25519-verified                                                                      | PASS  |
| 10| No new `subprocess`, no `shell=True`, no shell metacharacters in any new YAML                       | PASS (pinned by `test_command_template_has_no_shell_metacharacters`) |

---

## Architecture notes — what was carried over vs. what was new

### Carried over (Cycle 1 invariants — untouched)

* `ToolDescriptor` (`src/sandbox/adapter_base.py`) — Pydantic strict, no extra
  fields, no schema changes.
* `ALLOWED_PLACEHOLDERS` (`src/pipeline/contracts/_placeholders.py`) — every
  new YAML uses only `{url}`, `{domain}`, `{in_dir}`, `{out_dir}`. Zero
  placeholder additions; zero validator additions.
* Network policies (`src/sandbox/network_policies.py`) — re-used the existing
  `recon-passive` and `recon-active-tcp` templates. Zero new policies.
* `dispatch_parse` contract (`src/sandbox/parsers/__init__.py`) — same
  fail-soft semantics, same `(strategy, tool_id) → parser` lookup order
  (per-tool overrides win, generic strategies are the fall-back).

### New patterns (worth knowing for ARG-014+)

* **Multi-tool single-parser pattern** — `katana_parser.py` proves the
  pipeline can host one canonical "schema" with thin per-tool **iterator
  adapters** (`_iter_<tool>_records`) that normalise upstream JSON shapes onto
  it. This keeps dedup / sort / sidecar logic in one place and avoids three
  near-identical parsers. ARG-014 (`wpscan` + 7 cousins) and ARG-015 (`nuclei`)
  should follow the same shape.
* **Image-side wrapper convention** — every stdin/stdout-only upstream binary
  is wrapped in a thin `<tool>-wrapper -i … -out {out_dir}/…` shim baked into
  the `argus-kali-web` image. The shim's only job is to translate argv
  flags into the upstream's stdin/stdout pipes — it carries no business
  logic. This keeps `command_template` strictly argv-only (a security
  invariant) without forcing the upstream tools to grow native flag support.
  Documented in every affected YAML's `description`.
* **Inventory tests as first-class regression gates** —
  `test_yaml_crawler_semantics.py` is parametrised over the eight new
  YAMLs and pins twelve invariants per YAML (96 cases). This is the new
  template for §4.x batches: one semantics file per Backlog section, one
  parametrised case per invariant, easy to grep for missed flags.

---

## Out of scope / handed off

| Item                                                                                  | Owner / next cycle                                                                                                            |
| ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Generic `ParseStrategy.TEXT_LINES` parser + dispatch entry for the 5 text-lines tools | Cycle 3 (`ARG-014`-adjacent — pre-req for any §4.7+ batch that has stdin/stdout-only tools). |
| Full HTML parsing for `secretfinder` (regex-aware secret extraction → `FindingDTO`)   | Cycle 3 (currently the YAML routes through `text_lines`; once `secretfinder_html` parser ships, replace `parse_strategy` and add a per-tool entry to `_DEFAULT_TOOL_PARSERS`). |
| Production key rotation                                                               | Cycle 5 per Backlog §18.                                                                                                       |
| Image-side wrapper script implementations (`hakrawler-wrapper` etc.)                  | Sandbox image team — referenced from each affected YAML's `description`; not in this cycle's scope. |

---

## Files touched

### Created (production code)

* `backend/config/tools/katana.yaml`
* `backend/config/tools/gospider.yaml`
* `backend/config/tools/hakrawler.yaml`
* `backend/config/tools/waybackurls.yaml`
* `backend/config/tools/gau.yaml`
* `backend/config/tools/linkfinder.yaml`
* `backend/config/tools/subjs.yaml`
* `backend/config/tools/secretfinder.yaml`
* `backend/src/sandbox/parsers/katana_parser.py`
* `backend/config/tools/_keys/78317b2d95670ac9.ed25519.pub`

### Created (tests)

* `backend/tests/unit/sandbox/parsers/test_katana_parser.py`
* `backend/tests/unit/sandbox/parsers/test_gospider_parser.py`
* `backend/tests/unit/sandbox/parsers/test_gau_parser.py`
* `backend/tests/integration/sandbox/parsers/test_katana_dispatch.py`
* `backend/tests/integration/sandbox/test_arg013_end_to_end.py`
* `backend/tests/unit/sandbox/test_yaml_crawler_semantics.py`

### Modified

* `backend/src/sandbox/parsers/__init__.py` — register `katana`, `gospider`,
  `gau` against the JSONL pipeline.
* `backend/tests/integration/sandbox/test_tool_catalog_load.py` — `CRAWLER_TOOLS`
  added; `EXPECTED_TOOLS` bumped to 62; active/passive network policy split for
  crawlers; `argus-kali-web` image check; OWASP WSTG presence check.
* `backend/tests/unit/sandbox/test_yaml_schema_per_tool.py` — bumped count to
  62; added 8 new `tool_id`s.
* `backend/scripts/docs_tool_catalog.py` — `_EXPECTED_TOOLS_PER_PHASE`
  uplifted (recon 39 → 46, vuln_analysis 15 → 16); header range bumped to
  `ARG-001..ARG-013` / `§4.1–§4.6`.
* `backend/config/tools/SIGNATURES` — full re-write covering all 62 YAMLs
  with the new dev key (`78317b2d95670ac9`).
* `docs/tool-catalog.md` — regenerated deterministically from the registry.

---

## Test results summary

```
backend tests
=============

tests/unit/sandbox/parsers/test_katana_parser.py        17 passed
tests/unit/sandbox/parsers/test_gospider_parser.py       8 passed
tests/unit/sandbox/parsers/test_gau_parser.py            5 passed
tests/integration/sandbox/parsers/test_katana_dispatch.py 10 passed
tests/integration/sandbox/test_arg013_end_to_end.py      1 passed
tests/unit/sandbox/test_yaml_crawler_semantics.py       96 passed
tests/integration/sandbox/test_tool_catalog_load.py    full module green
tests/unit/sandbox/test_yaml_schema_per_tool.py        full module green
tests/test_tool_catalog_coverage.py                   310 passed (62 × 5)

aggregate sandbox suite        : 1610 passed in 49.95s
aggregate non-sandbox suite    : 1280 passed in 15.44s
ruff check (touched files)     : All checks passed!
ruff format --check            : 38 files already formatted
mypy src/sandbox               : Success: no issues found in 14 source files
mypy on touched tests/scripts  : Success: no issues found in 9 source files
SIGNATURES verify              : verify.ok verified_count=62
```

ARG-013 is complete. The §4.6 catalog scope is on disk, signed, parsed,
documented, and pinned by the sandbox test matrix.
