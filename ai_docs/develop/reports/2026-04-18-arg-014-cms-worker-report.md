# ARG-014 — Tool YAMLs §4.7 (CMS / platform-specific — 8 tools) + wpscan JSON parser — Completion Report

**Date:** 2026-04-18
**Cycle:** `argus-finalization-cycle2`
**Status:** COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` (§ARG-014, lines 222-267)
**Backlog:** `Backlog/dev1_.md` §4.7
**Dependencies:** ARG-011 (parser dispatch + multi-image stubs), ARG-012 (per-tool registry), ARG-013 (sidecar / cap / dedup pattern)

---

## Goal

Land Backlog §4.7 — the **CMS / platform-specific** scanner batch — on the
ARGUS sandbox without touching any Cycle 1 invariant. Concretely:

* Eight new signed `ToolDescriptor` YAMLs under `backend/config/tools/`.
* A deterministic **JSON parser** for WPScan that also serves as the
  format adapter for Droopescan (the second §4.7 tool that emits a stable,
  parseable JSON shape on disk).
* Parser dispatch wiring for the two JSON tools and pinned
  `text_lines` / `nuclei_jsonl` placement for the remaining six (handed
  off to Cycle 3 + ARG-015 respectively).
* Full unit + integration coverage for the new code path.
* Tool-inventory tests + auto-rendered tool catalog refreshed to match
  the new tool scope (Cycle 1: 62 → ARG-014: **+8** → 70). When this
  ticket landed, the parallel ARG-015 batch had already added 7 §4.8
  web-VA YAMLs (`nuclei`, `nikto`, `wapiti`, `arachni`, `skipfish`,
  `w3af_console`, `zap_baseline`), bringing the live catalog total to
  **77** at the moment of the final re-sign. The ARG-014 inventory
  tests are written `>= 70` (lower bound) and the end-to-end suite
  isolates to a tmp catalog of exactly the 8 §4.7 tools — see the
  *isolation strategy* note below.

All eight YAMLs are **`requires_approval: false`** (low-risk
enumeration / detection), run on the `argus-kali-web:latest` image, and
sit behind the `recon-active-tcp` `NetworkPolicy` template.

---

## Deliverables

### Tool descriptors (`backend/config/tools/`)

| `tool_id`              | phase           | risk  | network policy     | parse_strategy   | upstream                                                                  |
| ---------------------- | --------------- | ----- | ------------------ | ---------------- | ------------------------------------------------------------------------- |
| `wpscan`               | `vuln_analysis` | `low` | `recon-active-tcp` | `json_object`    | wpscanteam/wpscan                                                         |
| `joomscan`             | `vuln_analysis` | `low` | `recon-active-tcp` | `text_lines`     | OWASP/joomscan                                                            |
| `droopescan`           | `vuln_analysis` | `low` | `recon-active-tcp` | `json_object`    | SamJoan/droopescan                                                        |
| `cmsmap`               | `vuln_analysis` | `low` | `recon-active-tcp` | `text_lines`     | Dionach/CMSmap                                                            |
| `magescan`             | `vuln_analysis` | `low` | `recon-active-tcp` | `text_lines`     | steverobbins/magescan                                                     |
| `nextjs_check`         | `vuln_analysis` | `low` | `recon-active-tcp` | `nuclei_jsonl`   | nuclei `nextjs` tag set                                                   |
| `spring_boot_actuator` | `vuln_analysis` | `low` | `recon-active-tcp` | `nuclei_jsonl`   | nuclei `springboot,actuator` tag set                                      |
| `jenkins_enum`         | `vuln_analysis` | `low` | `recon-active-tcp` | `nuclei_jsonl`   | nuclei `jenkins` tag set                                                  |

Common invariants enforced for **every** §4.7 YAML:

* `image: argus-kali-web:latest` (the Dockerfile stub already lives in
  `sandbox/images/argus-kali-web/Dockerfile` from ARG-011).
* `cwe_hints` always includes `200` (Information Exposure); the five
  CMS-specific scanners (`wpscan`, `joomscan`, `droopescan`, `cmsmap`,
  `magescan`) and `jenkins_enum` also carry `1395` (Dependency on
  Vulnerable Third-Party Component). `nextjs_check` and
  `spring_boot_actuator` use `16` (Configuration) instead because their
  primary failure mode is misconfiguration, not a vulnerable upstream
  package.
* `owasp_wstg` includes `WSTG-INFO-08` (fingerprint web application
  framework) and `WSTG-CONF-04` (review old/backup files); the nuclei
  wrappers that gate authentication also carry `WSTG-ATHN-01`.
* `cpu_limit: "1"`, `memory_limit: "1Gi"`, `seccomp_profile: runtime/default`.
  `wpscan` runs with `cpu_limit: "2"` and `memory_limit: "2Gi"` because a
  full plugin/theme/user enumeration against a heavy site can span
  thousands of HTTP requests and parse a multi-MB JSON envelope.
* `default_timeout_s`: `1800` for `wpscan` (full plugin + theme + user
  enumeration); `1200` for the other CMS scanners; `900` for `magescan`;
  `600` for the three nuclei wrappers.
* `requires_approval: false` (no destructive operations — every tool is a
  detection / enumeration scanner).
* `command_template` is **argv-only**, no shell metacharacters (`;`,
  `&&`, `|`, backticks, `>`, `<`, `$()`, redirections, newlines). Pinned
  by `test_yaml_cms_semantics.py::test_command_template_has_no_shell_metacharacters`.
* The first argv token is always the real binary name (no leading shell
  wrapper). Pinned per-tool by
  `test_command_template_first_token_matches_expected_binary` so an
  accidental swap (e.g. nuclei → wpscan) breaks CI.
* For `wpscan` the descriptor only lists `--no-update`,
  `--disable-tls-checks` and `--random-user-agent` — the optional
  `WPSCAN_API_TOKEN` is read from the sandbox env by an image-side
  wrapper (no `{api_token}` placeholder in the argv to avoid leaking the
  token through process listings or audit logs).
* Every `description` carries the upstream author + canonical source URL
  and tags `Backlog/dev1_md §4.7` so
  `python -m scripts.docs_tool_catalog` renders provenance into
  `docs/tool-catalog.md`.

### Parser (`backend/src/sandbox/parsers/wpscan_parser.py`)

Single 753-line module that exports two public callables, both
strict-typed and `mypy --strict` clean:

| Symbol                    | Tool ID(s)   | Notes                                                                                                                 |
| ------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------- |
| `parse_wpscan_json`       | `wpscan`     | One canonical `FindingDTO` per dedup key across `interesting_findings`, `version`, `main_theme`, `themes`, `plugins`, `users`. Resolves the canonical `artifacts_dir/wpscan.json` first, then falls back to stdout. |
| `parse_droopescan_json`   | `droopescan` | Lightweight info-only adapter. One INFO finding per detected version candidate, theme, plugin, module, and user.       |

Per-record classification:

| Source block                                                                                                                | `FindingCategory` | `ConfidenceLevel`              | CWE hints     | OWASP-WSTG hints                |
| --------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------------------------------ | ------------- | ------------------------------- |
| `interesting_findings[*]` — server fingerprints, exposed config files, robots/readme leaks                                  | `INFO`            | `SUSPECTED`                    | `(200,)`      | `WSTG-INFO-08`, `WSTG-CONF-04`  |
| `version.vulnerabilities[*]`, `main_theme.vulnerabilities[*]`, `themes[<slug>].vulnerabilities[*]`, `plugins[<slug>].vulnerabilities[*]` | `MISCONFIG`       | `LIKELY` if ≥1 CVE attached, else `SUSPECTED` | `(1395,)` (component vuln) | `WSTG-INFO-08`, `WSTG-CONF-04`  |
| `users[*]` — enumerated WordPress users                                                                                     | `INFO`            | `SUSPECTED`                    | `(200,)`      | `WSTG-IDNT-04`                  |

Shared invariants:

* CVE refs are extracted from **both** the inline `cve` field and the
  `references.cve` array, normalised to `CVE-YYYY-...` form, sorted
  ascending and deduplicated.
* Severity is held implicitly through the CVSS sentinel
  (`cvss_v3_score=0.0`, `cvss_v3_vector=SENTINEL_CVSS_VECTOR`,
  `id=SENTINEL_UUID`). The downstream `Normalizer` lifts the score
  using NVD / EPSS data once CVE references land in `FindingDTO.epss_score`
  / `kev_listed`.
* Evidence sidecar: every parser writes a single
  `{artifacts_dir}/wpscan_findings.jsonl` JSON-Lines file (one record
  per finding, `tool_id` stamped per line so the downstream evidence
  pipeline can route per-tool).
* Hard cap: 5 000 unique findings per run — protects the worker from a
  runaway plugin enumeration on a heavily extended site. Subsequent
  records are dropped silently (logged via the parser's `_logger`,
  never raised).
* Records collapse on a stable key:
  - Interesting findings: `("interesting", to_s, type)`.
  - CMS / theme / plugin vulns: `(component, slug or "", title, *cves)`.
  - Users: `("user", username)`.
* Output ordering is deterministic — sorted by the dedup key so a
  re-run of WPScan against the same site yields the same finding
  sequence.
* Sidecar I/O failures are swallowed (logged as `WARNING`, never
  raised) — the parser's contract is "best-effort evidence persistence".
* Module-top imports only, no `subprocess`, no real network, no
  `os.environ` reads. Reuses the existing `safe_load_json` helper from
  `src.sandbox.parsers._base` so a malformed JSON envelope returns `[]`
  after a single structured `WARNING` log, never raises.

### Parser dispatch (`backend/src/sandbox/parsers/__init__.py`)

```python
"wpscan":     parse_wpscan_json,
"droopescan": parse_droopescan_json,
```

The three §4.7 `text_lines` tools (`joomscan`, `cmsmap`, `magescan`)
intentionally have **no** entry — they will land in Cycle 3 once a
generic `ParseStrategy.TEXT_LINES` strategy ships.

The three §4.7 `nuclei_jsonl` tools (`nextjs_check`,
`spring_boot_actuator`, `jenkins_enum`) are **pre-wired** here through
their `tool_id` keys; ARG-015 ships the
`ParseStrategy.NUCLEI_JSONL` handler concurrently and registers
`parse_nuclei_jsonl` for the same ids. From the §4.7 dispatch
perspective the wiring is now **fully functional** — no further
changes required when the ARG-015 worker lands its parser.

The integration test
`tests/integration/sandbox/parsers/test_wpscan_dispatch.py::test_text_lines_cms_tools_have_no_json_object_registration`
pins the text-only gap so future authors can't accidentally
short-circuit those tools through the JSON pipeline.

### Tests (`backend/tests/...`)

| File                                                                              | Tests | What it covers                                                                                                                        |
| --------------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `unit/sandbox/parsers/test_wpscan_parser.py`                                      | 34    | Per-record classification, CVE normalisation, dedup, ordering determinism, hard cap, malformed JSON fail-soft, sidecar emission, droopescan adapter, canonical artifact precedence. |
| `unit/sandbox/test_yaml_cms_semantics.py`                                         | 149   | Per-tool taxonomy invariants for all 8 §4.7 YAMLs (image, network policy, parse strategy split, CWE/WSTG hints, timeouts, resource limits, argv shell-metachar audit, binary name pin, description provenance). |
| `integration/sandbox/parsers/test_wpscan_dispatch.py`                             | 14    | Wpscan / droopescan route through `ParseStrategy.JSON_OBJECT` per-tool registry; the other six §4.7 tools are explicitly NOT registered for JSON_OBJECT; sidecar shape; determinism. |
| `integration/sandbox/test_arg014_end_to_end.py`                                   | 7     | End-to-end vertical slice running against an **isolated** tmp catalog (eight §4.7 YAMLs, ephemeral signing key) — descriptor loads with JSON_OBJECT, argv renders shell-clean, dispatch yields the expected 5-finding breakdown, sidecar persists, canonical artifact short-circuits stdout, the isolated catalog totals exactly **8** with every §4.7 tool present. |
| `integration/sandbox/test_tool_catalog_load.py` (extended `CMS_TOOLS` frozenset)  | n/a   | Adds the 8 §4.7 tool ids to the canonical inventory and asserts `summary.total >= 70` so the global coverage gate parametrises across whatever the catalog actually contains today. |
| `unit/sandbox/test_yaml_schema_per_tool.py` (extended `EXPECTED_TOOL_IDS`)        | n/a   | Pydantic schema parse, placeholder allow-list, image namespace, timeout bounds for every §4.7 YAML.                                   |

Coverage delta on `wpscan_parser.py`:

```
Name                                   Stmts   Miss  Cover   Missing
--------------------------------------------------------------------
src\sandbox\parsers\wpscan_parser.py     285     16    94%   430, 465, 476, 479, 525, 555, 559, 589, 664, 687-688, 747, 774, 788, 793, 804
```

The remaining 16 uncovered lines are defensive type-narrowing branches
(unreachable from valid WPScan / droopescan payloads but kept as
fail-soft guards). 94 % satisfies the ≥ 90 % parser-coverage gate from
the cycle plan acceptance criteria.

### Tool catalog (`docs/tool-catalog.md`)

Re-rendered via `python -m scripts.docs_tool_catalog --check`:

```
docs_tool_catalog.check_ok tools=77 path=D:\Developer\Pentest_test\ARGUS\docs\tool-catalog.md
```

Header references **ARG-001..ARG-015** (final regeneration ran after
the parallel ARG-015 batch landed); sections include `§4.7` and `§4.8`.
Per-phase totals at the moment of the final re-render:
* `recon`: unchanged (44 tools — no ARG-014 additions).
* `vuln_analysis`: 18 → **33** tools (+8 from §4.7 ARG-014, +7 from
  §4.8 ARG-015).

### Catalog signing (`backend/config/tools/SIGNATURES`)

```
$ python -m scripts.tools_sign verify --tools-dir config/tools \
    --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
{"event": "verify.ok", "signatures_path": "config\\tools\\SIGNATURES", "verified_count": 77}
```

All 77 YAMLs (8 ARG-014 + 7 ARG-015 + 62 prior) signed under
key id `0e6f8927232662c7` (Ed25519, 32-byte raw public key in
`_keys/0e6f8927232662c7.ed25519.pub`). The catalog was re-signed
after ARG-015 landed because their `w3af_console.yaml` was modified
post the original ARG-014 signing pass (parallel batch reality).
Audit trail of historical public keys is preserved (7 `.pub` files in
`_keys/`); the matching private key was deleted after signing per the
`_keys/README.md` workflow.

---

## Acceptance gate

```powershell
$ python -m scripts.tools_sign verify --tools-dir config/tools `
    --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
{"event": "verify.ok", "signatures_path": "config\\tools\\SIGNATURES", "verified_count": 77}

$ python -m pytest tests/unit/sandbox tests/integration/sandbox `
    tests/test_tool_catalog_coverage.py
2627 passed in 71.28s

$ python -m pytest tests/unit/sandbox/parsers/test_wpscan_parser.py `
    tests/integration/sandbox/parsers/test_wpscan_dispatch.py `
    --cov=src.sandbox.parsers.wpscan_parser --cov-report=term-missing
48 passed in 1.77s
TOTAL                                    285     16    94%

$ python -m mypy --strict src/sandbox/parsers/wpscan_parser.py `
    src/sandbox/parsers/__init__.py
Success: no issues found in 2 source files

$ python -m ruff check src/sandbox/parsers/wpscan_parser.py `
    src/sandbox/parsers/__init__.py tests/unit/sandbox/parsers/test_wpscan_parser.py `
    tests/integration/sandbox/parsers/test_wpscan_dispatch.py `
    tests/integration/sandbox/parsers/test_dispatch_registry.py `
    tests/unit/sandbox/test_yaml_cms_semantics.py `
    tests/integration/sandbox/test_arg014_end_to_end.py `
    tests/integration/sandbox/test_dry_run_e2e.py `
    tests/integration/sandbox/test_tool_catalog_load.py `
    tests/unit/sandbox/test_yaml_schema_per_tool.py scripts/docs_tool_catalog.py
All checks passed!

$ python -m ruff format --check <same paths>
11 files already formatted

$ python -m scripts.docs_tool_catalog --check
docs_tool_catalog.check_ok tools=77 path=D:\Developer\Pentest_test\ARGUS\docs\tool-catalog.md
```

All gates green. No regressions in ARG-011 / ARG-012 / ARG-013 — the
2627-test sandbox suite passes, including the parallel ARG-015 work.

### Side-fixes pulled in to keep the suite green

The parallel ARG-015 batch landed concurrently with this one and broke
two assertions that ARG-014 inherited because the relevant tests load
the *production* catalog. Surgical fixes were folded in:

1.  `tests/integration/sandbox/parsers/test_dispatch_registry.py` —
    `test_default_registry_does_not_register_unimplemented_strategies`
    and `test_reset_registry_restores_default_handlers` updated to
    expect `ParseStrategy.NUCLEI_JSONL` in the default surface (now
    registered by ARG-015's `parse_nuclei_jsonl`).
2.  `tests/integration/sandbox/test_dry_run_e2e.py` — `_tool_job_for`
    now sets `requires_approval` + `approval_id` derived from the
    descriptor so ARG-015's medium-risk `arachni` / `skipfish` /
    `w3af_console` (`requires_approval: true`) pass the
    `ToolJob.__post_init__` invariant.

Both fixes are scoped, additive, and orthogonal to the ARG-014 surface.

---

## Architecture notes & non-obvious decisions

1.  **Eight tools, two parsers — by design.** §4.7 is a heterogeneous
    bucket (CMS scanners + framework exposure checks). Only WPScan and
    Droopescan emit a stable, parseable JSON envelope; the other six
    either stream text (`joomscan`, `cmsmap`, `magescan`) or wrap nuclei
    templates (`nextjs_check`, `spring_boot_actuator`, `jenkins_enum`).
    Building eight bespoke parsers in Cycle 2 would have duplicated work
    that ARG-015 (nuclei) and Cycle 3 (text_lines) will absorb anyway.
    The integration tests pin the gap so the YAMLs cannot silently
    short-circuit through the wrong strategy when the missing parsers
    land.

2.  **No `{api_token}` placeholder.** WPScan optionally consumes the
    `WPSCAN_API_TOKEN` env var for CVE / WPVulnDB lookups. Embedding it
    in the argv would leak the secret through `/proc/<pid>/cmdline`,
    Kubernetes audit logs, and any future replay-command sanitiser.
    The descriptor instead relies on an image-side wrapper that reads
    the env var inside the sandbox container — the YAML stays
    placeholder-clean and the secret never touches the renderer.
    Documented inline in `wpscan.yaml::description`.

3.  **Severity through the confidence ladder, not CVSS.** The parser
    operates in the contract layer where the CVSS score is held at the
    sentinel (`0.0`, `SENTINEL_CVSS_VECTOR`). A `LIKELY` confidence
    when ≥1 CVE is attached signals "the upstream tracker accepted this
    vuln; WPScan still depends on a version match for confirmation".
    The downstream `Normalizer` lifts the score using NVD / EPSS data
    when the CVE list lands in `FindingDTO.epss_score` / `kev_listed`.
    This keeps the parser pure (no network, no CVE database lookup) and
    centralises severity policy in one place.

4.  **Single shared sidecar (`wpscan_findings.jsonl`).** Both parsers
    write to the same file and stamp every record with its source
    `tool_id`. Mirrors the `katana_parser` pattern (one filename per
    parser family) and lets the downstream evidence pipeline route
    per-tool with a single open / scan instead of N file probes.

5.  **Per-tool `cwe_hints` split for nuclei wrappers.**
    `nextjs_check` and `spring_boot_actuator` ship `cwe_hints: [200, 16]`
    (Information Exposure + Configuration) instead of the universal
    `1395`. Their primary failure mode is a misconfigured framework
    (Next.js middleware bypass via CVE-2025-29927, exposed Spring Boot
    Actuator endpoints), not a vulnerable upstream package. Pinned in
    `test_yaml_cms_semantics.py::test_cms_cwe_includes_vulnerable_component`
    via an explicit exemption list so the rule stays tight.

6.  **Isolated tmp catalog for the e2e suite — defence-in-depth.**
    `test_arg014_end_to_end.py` builds a fresh, signed mirror of just
    the eight §4.7 YAMLs under `tmp_path` (ephemeral keypair, scoped
    to the test process) and runs every assertion against that
    `ToolRegistry`. The production catalog is *never* loaded directly
    from the e2e suite — `ToolRegistry.load()` is fail-closed, so a
    single broken peer YAML (e.g. an in-flight ARG-015+ schema error)
    would otherwise mask all of ARG-014's vertical-slice assertions.
    The sister whole-catalog invariants (`>= 70` total, per-phase
    counts, signature integrity) live in
    `tests/integration/sandbox/test_tool_catalog_load.py` where
    parallel-batch friction is the explicit subject under test.

---

## Risks / out-of-scope

* `joomscan` / `cmsmap` / `magescan` text-output parsing — deferred to
  Cycle 3 once `ParseStrategy.TEXT_LINES` ships. Their YAMLs are wired
  with `parse_strategy: text_lines` so the dispatch will route correctly
  the moment the strategy is registered.
* `nextjs_check` / `spring_boot_actuator` / `jenkins_enum` functional
  parsing — **NOW UNBLOCKED** by ARG-015's `parse_nuclei_jsonl`. The
  three §4.7 YAMLs are pre-wired against `tool_id` keys in
  `_DEFAULT_TOOL_PARSERS` and ARG-015 registered the same ids alongside
  the flagship `nuclei` tool. No follow-up YAML edit needed.
* CVE → CVSS hydration is intentionally NOT done in the parser; lives in
  the downstream `Normalizer`. Same convention as ARG-013 (`katana`).
* No real-network test — fixtures synthesise the WPScan JSON envelope.
  A live fixture against a vulnerable WordPress on a sandbox network is
  Cycle 6 (DoD §19) territory.

---

## Files touched (summary)

```
A  backend/config/tools/cmsmap.yaml
A  backend/config/tools/droopescan.yaml
A  backend/config/tools/jenkins_enum.yaml
A  backend/config/tools/joomscan.yaml
A  backend/config/tools/magescan.yaml
A  backend/config/tools/nextjs_check.yaml
A  backend/config/tools/spring_boot_actuator.yaml
A  backend/config/tools/wpscan.yaml
M  backend/config/tools/SIGNATURES                              (62 → 77 entries after final re-sign)
A  backend/config/tools/_keys/0e6f8927232662c7.ed25519.pub      (32-byte raw key, post-ARG-015 re-sign)
A  backend/src/sandbox/parsers/wpscan_parser.py                 (~810 LoC, mypy --strict clean)
M  backend/src/sandbox/parsers/__init__.py                      (registered wpscan + droopescan + pre-wired §4.7 nuclei callers)
A  backend/tests/unit/sandbox/parsers/test_wpscan_parser.py     (34 tests, 94 % coverage)
A  backend/tests/unit/sandbox/test_yaml_cms_semantics.py        (149 parametrised tests)
A  backend/tests/integration/sandbox/parsers/test_wpscan_dispatch.py  (14 tests)
A  backend/tests/integration/sandbox/test_arg014_end_to_end.py  (7 vertical-slice tests, isolated tmp catalog)
M  backend/tests/integration/sandbox/test_tool_catalog_load.py  (CMS_TOOLS frozenset, summary.total >= 70)
M  backend/tests/unit/sandbox/test_yaml_schema_per_tool.py      (added 8 §4.7 tool ids)
M  backend/tests/integration/sandbox/parsers/test_dispatch_registry.py (NUCLEI_JSONL added to default surface — side-fix for ARG-015)
M  backend/tests/integration/sandbox/test_dry_run_e2e.py        (synthetic approval_id for high/destructive tools — side-fix for ARG-015)
M  backend/scripts/docs_tool_catalog.py                         (header bump ARG-001..ARG-015, §4.7 + §4.8 added)
M  docs/tool-catalog.md                                         (regenerated, 77 tools)
M  ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md (ARG-014 → Completed)
M  ai_docs/develop/reports/2026-04-18-arg-014-cms-worker-report.md  (this file)
```

---

## Hand-off

* Catalog total at the moment of the final re-sign: **77** (Cycle 1: 35;
  ARG-011: +9 → 44; ARG-012: +10 → 54; ARG-013: +8 → 62; **ARG-014: +8 → 70**;
  ARG-015 (parallel): +7 → **77**).
* The three §4.7 `nuclei_jsonl` tools (`nextjs_check`,
  `spring_boot_actuator`, `jenkins_enum`) are now **fully functional**:
  ARG-015 landed `parse_nuclei_jsonl` in the same cycle and registered
  it for those `tool_id`s. They start emitting findings as soon as the
  cluster runs them.
* No production runtime is touched: the new module is import-only and
  the YAMLs are inert until a `ToolRegistry` reload is triggered.
