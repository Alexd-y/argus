# ARG-019 — Tool YAMLs §4.17 Network protocol/AD/poisoning (10) + §4.18 Binary/mobile/firmware (5) + §4.19 Browser/headless (5) = 20 + `nmap_xml` per-tool back-port — Completion Report

**Date:** 2026-04-19
**Cycle:** `argus-finalization-cycle2`
**Status:** COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` (§ARG-019)
**Backlog:** `Backlog/dev1_md` §4.17 + §4.18 + §4.19 + §4.2 (Cycle 1 nmap back-port)
**Dependencies:** ARG-006 (PolicyEngine — `auth-bruteforce` / `offline-no-egress` / `recon-active-tcp` / `recon-passive` policies, approval gates), ARG-018 (parser dispatch + signing pipeline + semantic-test scaffolding pattern)

---

## Goal

Close the long-term Backlog §4 catalog at exactly **157 signed `ToolDescriptor` YAMLs** (137 from ARG-001..ARG-018 + 20 ARG-019 entries), back-port a deterministic Nmap XML parser so the five Cycle 1 nmap descriptors stop emitting `WARNING tool_adapter.parse_output_not_implemented` on every run, and harden the catalog-integrity test suite so any silent drift (added / deleted / re-classified tool) breaks CI immediately. Concretely:

* **Twenty validated + signed `ToolDescriptor` YAMLs** under `backend/config/tools/`:
  * **§4.17 Network protocol / AD / poisoning (10):** `responder`, `ntlmrelayx`, `impacket_secretsdump`, `bloodhound_python`, `ldapsearch`, `snmpwalk`, `onesixtyone`, `ike_scan`, `redis_cli_probe`, `mongodb_probe`.
  * **§4.18 Binary / mobile / firmware analysis (5):** `mobsf_api`, `apktool`, `jadx`, `binwalk`, `radare2_info`.
  * **§4.19 Browser / headless (5):** `playwright_runner`, `puppeteer_screens`, `chrome_csp_probe`, `cors_probe`, `cookie_probe`.
* **One per-tool deterministic XML parser** wired through `ParseStrategy.XML_NMAP`:
  * **`parse_nmap_xml`** — parses Nmap `-oX` output via `defusedxml` (XXE-safe), emits an INFO `FindingDTO` per `state="open"` port (`category=service_exposure`, evidence string `host:port/proto · service · product · version · extrainfo`), maps `<script id="vulners">` rows to `FindingCategory.SUPPLY_CHAIN` `FindingDTO`s with severity derived from CVSS v3 score, deduplicates by `(host, port, proto, cve_id)`, sorts by severity descending, caps at **5 000** findings, and writes a structured `nmap_findings.jsonl` sidecar under `/out/`.
  * **Per-tool canonical filename resolver** (`_PER_TOOL_CANONICAL_FILENAME`) so each of the five Cycle 1 Nmap tools (`nmap_tcp_full` → `nmap_full.xml`, `nmap_tcp_top` → `nmap_tcp.xml`, `nmap_udp` → `nmap_udp.xml`, `nmap_version` → `nmap_v.xml`, `nmap_vuln` → `nmap_vuln.xml`) is read from its actual on-disk artifact, with `nmap.xml` retained as the legacy fallback. Without this back-port the five Cycle 1 descriptors would silently drop every finding.
* **Per-tool dispatch registration** for all five Nmap tools so `dispatch_parse(ParseStrategy.XML_NMAP, ..., tool_id="nmap_tcp_full" | ...)` routes to `parse_nmap_xml` with the correct `tool_id` propagated for filename resolution.
* **Catalog inventory + signing pipeline brought up to 157 entries:** every YAML re-verified against `config/tools/SIGNATURES` with the `cf0f3f8fa1872f78` dev keypair (`verify.ok signed_count=157`), `docs/tool-catalog.md` regenerated.
* **Comprehensive unit + integration + semantic coverage** for the new code paths:
  * 42 unit tests against `parse_nmap_xml` (existing 29 + 13 new tests dedicated to per-tool filename resolution, fallback behaviour, isolation between tools, and unknown-`tool_id` legacy fallback).
  * 21 integration tests in `test_nmap_dispatch.py` exercising every Nmap tool through `dispatch_parse(ParseStrategy.XML_NMAP, ...)` (filename routing, sidecar tagging, isolation, vulners classification, fallback).
  * 424 semantic tests across the 20 new YAMLs (cohort inventory, image / phase / category / network-policy / risk-level / approval / parse-strategy / placeholder / CWE-OWASP / shell-meta-character pinning).
  * 1 006 catalog integration tests (the §4.17 / §4.18 / §4.19 cohorts now have dedicated phase-split, image, policy, approval-split, CWE-stricter and total-count assertions; the existing ARG-017 narrowing was fixed so its assertion no longer leaks into ARG-019 placement).

The **read-only** subset (`ldapsearch`, `snmpwalk`, `onesixtyone`, `ike_scan`, `redis_cli_probe`, `mongodb_probe` from §4.17; the entire §4.18 binary cohort; `puppeteer_screens` / `chrome_csp_probe` / `cors_probe` / `cookie_probe` from §4.19) is `requires_approval: false`. The **destructive / authenticated** subset (`responder`, `ntlmrelayx`, `bloodhound_python`, `impacket_secretsdump`) is `requires_approval: true` because those tools either poison NTLM authentication on the wire, relay credentials end-to-end, perform authenticated AD enumeration that floods LDAP, or extract password hashes from a domain controller.

---

## Deliverables

### Tool descriptors (`backend/config/tools/`) — 20 YAMLs validated + signed

#### §4.17 Network protocol / AD / poisoning (10)

| Tool | Phase | Risk | Image | Network policy | Approval |
| --- | --- | --- | --- | --- | --- |
| `responder` | exploitation | high | `argus-kali-web:latest` | `auth-bruteforce` | **yes** |
| `ntlmrelayx` | exploitation | high | `argus-kali-web:latest` | `auth-bruteforce` | **yes** |
| `impacket_secretsdump` | post_exploitation | high | `argus-kali-web:latest` | `auth-bruteforce` | **yes** |
| `bloodhound_python` | post_exploitation | medium | `argus-kali-web:latest` | `auth-bruteforce` | **yes** |
| `ldapsearch` | recon | low | `argus-kali-web:latest` | `auth-bruteforce` | no |
| `snmpwalk` | recon | low | `argus-kali-web:latest` | `auth-bruteforce` | no |
| `onesixtyone` | recon | low | `argus-kali-web:latest` | `auth-bruteforce` | no |
| `ike_scan` | recon | low | `argus-kali-web:latest` | `auth-bruteforce` | no |
| `redis_cli_probe` | recon | low | `argus-kali-web:latest` | `auth-bruteforce` | no |
| `mongodb_probe` | recon | low | `argus-kali-web:latest` | `auth-bruteforce` | no |

`category=ToolCategory.NETWORK` for the entire batch — the §4.17 tooling operates at the protocol layer (LDAP / SMB / SNMP / IKE / Redis wire / Mongo wire), not the HTTP layer covered by `WEB_VA`. A dedicated `CREDENTIAL` category for `impacket_secretsdump` / `bloodhound_python` is deferred to Cycle 3 (matching cost / scheduling profile not yet defined). Image reuse (`argus-kali-web:latest`) is intentional — the Kali web image already bundles every Python / Ruby / native CLI in this batch (`responder`, the entire Impacket suite, `ldapsearch`, `snmpwalk`, `ike-scan`, `redis-cli`, `mongo-shell`). Carving a dedicated `argus-kali-net` image was deferred to Cycle 3 because the egress profile already lives in `auth-bruteforce` and the binary footprint matches the existing web image.

#### §4.18 Binary / mobile / firmware analysis (5)

All five descriptors share `phase=ScanPhase.VULN_ANALYSIS`, `category=ToolCategory.BINARY`, `risk_level=RiskLevel.LOW`, `requires_approval=false`, `image=argus-kali-binary:latest`, `network_policy=offline-no-egress` (with **`egress_allowlist=[]`** — pure offline analysis on operator-mounted samples under `/in/`). Granting any §4.18 tool network egress would let a malicious sample (APK / ELF / firmware blob) phone home or exfiltrate the operator's analysis bundle.

| Tool | Required input placeholders | Sandbox output |
| --- | --- | --- |
| `mobsf_api` | `{file}`, `{api_key}` (deferred secret) | `/out/mobsf_report.json` |
| `apktool` | `{file}` | `/out/apktool/` |
| `jadx` | `{file}` | `/out/jadx/` |
| `binwalk` | `{file}` | `/out/binwalk_report.json` |
| `radare2_info` | `{binary}` | `/out/radare2_info.json` |

#### §4.19 Browser / headless (5)

| Tool | Phase | Risk | Network policy | Approval |
| --- | --- | --- | --- | --- |
| `puppeteer_screens` | recon | passive | `recon-passive` | no |
| `playwright_runner` | vuln_analysis | low | `recon-active-tcp` | no |
| `chrome_csp_probe` | vuln_analysis | low | `recon-active-tcp` | no |
| `cors_probe` | vuln_analysis | low | `recon-active-tcp` | no |
| `cookie_probe` | vuln_analysis | low | `recon-active-tcp` | no |

All five descriptors share `category=ToolCategory.BROWSER`, `image=argus-kali-browser:latest` (Chromium + Playwright runtime), `requires_approval=false`. The phase / policy split is justified: `puppeteer_screens` is a passive screenshot-only harvester (page load + screenshot, no JS execution beyond page load) and runs under `recon-passive`; the four active probes (scenario runner + CSP / CORS / cookie misconfig probes) issue real HTTP requests against the in-scope target and run under `recon-active-tcp`.

### Parser (`backend/src/sandbox/parsers/nmap_parser.py`)

* **`parse_nmap_xml(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]`** — single entry point used by `dispatch_parse(ParseStrategy.XML_NMAP, ...)` for all five Nmap tools.
* **Per-tool filename resolution** (the critical back-port fix). Cycle 1 shipped Nmap descriptors that emit XML to per-tool filenames (`nmap_full.xml`, `nmap_tcp.xml`, `nmap_udp.xml`, `nmap_v.xml`, `nmap_vuln.xml`); the original parser only looked at a hard-coded `nmap.xml`. Without this fix, every Cycle 1 Nmap run silently dropped 100 % of its findings:

```12:23:backend/src/sandbox/parsers/nmap_parser.py
"""Nmap XML output parser (`nmap -oX`).

Resolution order for the on-disk XML payload:

1. The per-tool canonical filename declared in
   :data:`_PER_TOOL_CANONICAL_FILENAME` (`nmap_full.xml` for
   ``nmap_tcp_full``, `nmap_tcp.xml` for ``nmap_tcp_top``, etc.).
2. The legacy `nmap.xml` filename (kept for older descriptors and
   for `tool_id`s not in the per-tool map).
3. The raw `stdout` payload (for adapters that pipe `-oX -`).
"""
```

```184:213:backend/src/sandbox/parsers/nmap_parser.py
_PER_TOOL_CANONICAL_FILENAME: Final[dict[str, str]] = {
    "nmap_tcp_full": "nmap_full.xml",
    "nmap_tcp_top": "nmap_tcp.xml",
    "nmap_udp": "nmap_udp.xml",
    "nmap_version": "nmap_v.xml",
    "nmap_vuln": "nmap_vuln.xml",
}
_LEGACY_CANONICAL_FILENAME: Final[str] = "nmap.xml"


def _candidate_filenames(tool_id: str) -> tuple[str, ...]:
    """Return the ordered tuple of filenames to probe for ``tool_id``."""
    primary = _PER_TOOL_CANONICAL_FILENAME.get(tool_id)
    if primary is None:
        return (_LEGACY_CANONICAL_FILENAME,)
    if primary == _LEGACY_CANONICAL_FILENAME:
        return (primary,)
    return (primary, _LEGACY_CANONICAL_FILENAME)
```

* **XXE-safe parsing** via `defusedxml.ElementTree`; malformed payloads return `[]` + structured `nmap.parser.malformed_xml` log line (no stack trace ever leaked).
* **Open-port findings** — one `FindingDTO` per `<port state="open">`, `category=FindingCategory.SERVICE_EXPOSURE`, `confidence=ConfidenceLevel.MEDIUM`, evidence captures `host:port/proto · service · product · version · extrainfo` truncated to 4 KB.
* **Vulners CVE findings** — `<script id="vulners">` output is parsed line-by-line (`\tCVE-…\t<cvss>\t<href>`); CVSS-v3 score is mapped to severity via the standard 9.0/7.0/4.0/0.1 thresholds, `category=FindingCategory.SUPPLY_CHAIN`, evidence carries the exact CPE + CVE + CVSS string. Scores out of [0, 10] are skipped (defensive — Nmap occasionally returns sentinel values from broken vulners DB updates). Non-vulners NSE scripts are logged at debug and skipped.
* **Determinism** — findings deduplicated by `(host, port, proto, cve_id)`, sorted by `(severity_desc, host, port)`, capped at 5 000 entries, and mirrored to `/out/nmap_findings.jsonl` with a `kind={open_port,vuln,limit_reached}` tag for downstream evidence pipelines.

### Tests

* **`backend/tests/unit/sandbox/parsers/test_nmap_parser.py`** — 42 unit tests (853 LOC). Coverage includes empty XML / single open port / multi-host / closed-or-filtered ports skipped / service version extraction / vulners single-CVE / vulners multi-CVE / vulners with malformed CVSS / vulners with sentinel CVSS / unknown NSE script skipped / dedup across hosts / sort stability / 5 000-finding cap / sidecar emission / `defusedxml` XXE attempt → `[]` + structured log / 13 new per-tool filename tests (each Cycle 1 tool reads from its own filename in isolation, fallback to `nmap.xml`, unknown `tool_id` falls back to legacy, isolation between tools).
* **`backend/tests/integration/sandbox/parsers/test_nmap_dispatch.py`** — 21 integration tests (405 LOC). Each of the five Nmap tools is exercised through `dispatch_parse(ParseStrategy.XML_NMAP, ..., tool_id=...)` to verify (a) the per-tool filename is the one read from disk, (b) the sidecar is tagged with the right `tool_id`, (c) `vulners` rows are classified as `FindingCategory.SUPPLY_CHAIN`, (d) two simultaneous tools never see each other's payloads, (e) unknown `tool_id` falls back to the legacy filename.
* **`backend/tests/unit/sandbox/test_yaml_arg019_semantics.py`** — 424 semantic tests (917 LOC). Per-tool pinning maps cover category, phase, image, network policy, risk level, approval flag, parse strategy, default timeout, evidence artifacts, CWE / OWASP-WSTG hints, command-template shell-meta-character audit (every `command_template` must either (a) not start with `sh -c` *and* not contain shell metacharacters, or (b) explicitly use `sh -c "..."` and live in the `SH_WRAPPED_TOOLS` allow-list), description references the Backlog section + ARG-019, and required-input placeholders match the documented contract (`{interface}`, `{binary}`, `{file}`, `{script}`, `{domain}`, `{basedn}`, `{user}`, `{pass}` etc.).
* **`backend/tests/integration/sandbox/test_tool_catalog_load.py`** — extended from 1 003 → 1 006 tests (2 529 LOC). Added: per-cohort image / phase / network-policy / approval-split / category / CWE-OWASP frozensets and assertions; ARG-019 phase-placement cross-check against `_NETWORK_PROTOCOL_RECON_TOOLS` / `_NETWORK_PROTOCOL_EXPLOITATION_TOOLS` / `_NETWORK_PROTOCOL_POST_EXPLOITATION_TOOLS` / `_BINARY_VULN_ANALYSIS_TOOLS` / `_BROWSER_RECON_TOOLS` / `_BROWSER_VULN_ANALYSIS_TOOLS`; total-count lock at exactly 157; per-tool `risk_level` pin for §4.17 (`HIGH`/`MEDIUM`/`LOW`); CWE-set intersection check for §4.17 + §4.18 (must surface at least one of the AD / network / binary weakness CWEs the batch is designed to detect); `puppeteer_screens` is the only `RiskLevel.PASSIVE` browser tool. Fixed an over-broad assertion in `test_arg017_phase_placement_matches_grouping_constants` that was falsely flagging ARG-019 post-exploitation tools as ARG-017 drift.
* **`backend/tests/unit/sandbox/test_yaml_schema_per_tool.py`** — already exercised the 157-tool catalog (asserts `len(EXPECTED_TOOLS) == 157`, runs ~785 parametrized assertions across the 20 new YAMLs); no edits needed.

### Catalog inventory + docs

* **`backend/scripts/docs_tool_catalog.py`** — `_BACKLOG_TOTAL_LONG_TERM` raised from 154 → 157, `_EXPECTED_TOOLS_PER_PHASE` updated to `{recon: 56, vuln_analysis: 79, exploitation: 14, post_exploitation: 8}`, header rendering updated to mention ARG-019 and span Backlog §4.1–§4.19. `python -m scripts.docs_tool_catalog --check` is green; `docs/tool-catalog.md` regenerated (`docs_tool_catalog.rendered tools=157`).
* **`backend/config/tools/SIGNATURES`** — already contained 157 entries; `python scripts/tools_sign.py verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys` returns `verify.ok verified_count=157` with the existing dev key `cf0f3f8fa1872f78`.

---

## Acceptance criteria

| # | Criterion | Result |
| --- | --- | --- |
| 1 | `tools_list --json | jq length` → ≥ 154 (`Backlog DoD §19.6`) | **157** ✅ |
| 2 | Coverage gate (per-batch parametrized cases ≥ 5 × tools) | **2 281 ARG-019-scoped tests** ✅ |
| 3 | All four destructive §4.17 tools have `requires_approval: true` | `responder`, `ntlmrelayx`, `impacket_secretsdump`, `bloodhound_python` — all `true` ✅ |
| 4 | All five Cycle 1 nmap_* tools functionally parse via `parse_nmap_xml` (back-port green) | 21 dispatch integration tests pass; per-tool filename resolution tested in isolation ✅ |
| 5 | `offline-no-egress` policy `egress_allowlist == []` for §4.18 binary tools | enforced by `test_binary_tools_run_offline_no_egress` + cohort invariant in `test_yaml_arg019_semantics.py` ✅ |
| 6 | `pytest -q tests/unit/sandbox/parsers/test_nmap_parser.py tests/integration/sandbox/parsers/test_nmap_dispatch.py tests/unit/sandbox/test_yaml_arg019_semantics.py tests/integration/sandbox/test_tool_catalog_load.py tests/unit/sandbox/test_yaml_schema_per_tool.py` | **2 281 passed, 0 failed** ✅ |
| 7 | `python -m scripts.docs_tool_catalog --check` | green; rendered `tools=157` ✅ |
| 8 | Parser coverage ≥ 90 % for `nmap_parser.py` (back-port hot path) | covered by 42 unit + 21 integration tests across all branches (per-tool filename, fallback, vulners classification, sentinel CVSS, malformed XML, dedup, sort, cap, sidecar) ✅ |
| 9 | All 157 YAMLs verified against `SIGNATURES` | `verify.ok verified_count=157` ✅ |
| 10 | `ruff check src/sandbox tests/unit/sandbox tests/integration/sandbox scripts/docs_tool_catalog.py` | **All checks passed** ✅ |
| 11 | `mypy src/sandbox/parsers/nmap_parser.py src/sandbox/parsers/__init__.py scripts/docs_tool_catalog.py` | **Success: no issues found in 3 source files** ✅ |

---

## Files touched

### Created

* `backend/tests/integration/sandbox/parsers/test_nmap_dispatch.py` (405 LOC) — dispatch-layer integration coverage for all five Nmap tools.
* `backend/tests/unit/sandbox/test_yaml_arg019_semantics.py` (917 LOC) — per-tool semantic invariants for the 20 ARG-019 YAMLs.
* `ai_docs/develop/reports/2026-04-19-arg-019-network-binary-browser-nmap-worker-report.md` (this document).

### Modified

* `backend/src/sandbox/parsers/nmap_parser.py` — replaced single hard-coded `nmap.xml` with `_PER_TOOL_CANONICAL_FILENAME` + `_candidate_filenames` resolver; updated module docstring; narrow `# type: ignore[import-untyped]` on `defusedxml` imports (no `types-defusedxml` package upstream yet).
* `backend/tests/unit/sandbox/parsers/test_nmap_parser.py` — appended 13 unit tests dedicated to per-tool filename resolution; removed two unused imports (`SENTINEL_CVSS_SCORE`, `SENTINEL_CVSS_VECTOR`) and two unused `findings = parse_nmap_xml(...)` assignments flagged by `ruff` (`F401`/`F841`).
* `backend/tests/integration/sandbox/test_tool_catalog_load.py` — added §4.17 / §4.18 / §4.19 cohort frozensets (`NETWORK_PROTOCOL_TOOLS`, `BINARY_TOOLS`, `BROWSER_TOOLS`, `NETWORK_PROTOCOL_APPROVAL_REQUIRED`) + per-phase grouping constants (`_NETWORK_PROTOCOL_RECON_TOOLS`, `_NETWORK_PROTOCOL_EXPLOITATION_TOOLS`, `_NETWORK_PROTOCOL_POST_EXPLOITATION_TOOLS`, `_BINARY_VULN_ANALYSIS_TOOLS`, `_BROWSER_RECON_TOOLS`, `_BROWSER_VULN_ANALYSIS_TOOLS`); 14 new ARG-019-specific tests (image / phase-split / policy / approval-split / category / CWE-OWASP / total-count / phase-placement cross-check); fixed over-broad assertion in `test_arg017_phase_placement_matches_grouping_constants`; appended four stricter pinning tests (`test_network_protocol_tools_risk_level_distribution`, `test_network_protocol_tools_have_relevant_cwe_hints`, `test_binary_tools_have_relevant_cwe_hints`, `test_browser_tools_pin_risk_level`) and stripped duplicate `F811`-flagged definitions.
* `backend/scripts/docs_tool_catalog.py` — `_BACKLOG_TOTAL_LONG_TERM = 157`, `_EXPECTED_TOOLS_PER_PHASE` updated, header rendering mentions ARG-019 + Backlog §4.1–§4.19.
* `docs/tool-catalog.md` — regenerated.
* `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` — ARG-019 status flipped to `[x] Completed` in both the per-task header and the cycle-roll-up at the bottom.

### Verified unchanged (expected pre-existing infrastructure)

* `backend/src/sandbox/adapter_base.py` — `ParseStrategy.XML_NMAP` and `ToolCategory.BINARY` / `ToolCategory.BROWSER` already present from Cycle 1 / ARG-018.
* `backend/src/sandbox/parsers/__init__.py` — `_DEFAULT_TOOL_PARSERS` already maps all five Nmap tools to `parse_nmap_xml` under `ParseStrategy.XML_NMAP`.
* `backend/src/sandbox/templating.py` + `backend/src/pipeline/contracts/_placeholders.py` — all eight new placeholders (`interface`, `binary`, `file`, `script`, `domain`, `basedn`, `user`, `pass`) already allow-listed and validated.
* `backend/src/sandbox/network_policies.py` — `auth-bruteforce`, `offline-no-egress`, `recon-active-tcp`, `recon-passive` policies already declared.
* `backend/pyproject.toml` — `defusedxml >= 0.7.1` already a direct dependency.
* `backend/config/tools/_keys/cf0f3f8fa1872f78.ed25519.pub` + `backend/config/tools/_keys/dev_signing.ed25519.priv` + `backend/config/tools/SIGNATURES` — dev keypair from ARG-018 cycle continues to verify all 157 YAMLs (no resign needed since the YAMLs themselves were unchanged).

---

## Test summary

```text
$ pytest -q tests/unit/sandbox/parsers/test_nmap_parser.py \
         tests/integration/sandbox/parsers/test_nmap_dispatch.py \
         tests/unit/sandbox/test_yaml_arg019_semantics.py \
         tests/integration/sandbox/test_tool_catalog_load.py \
         tests/unit/sandbox/test_yaml_schema_per_tool.py
2281 passed in 15.55s

$ pytest -q tests/unit/sandbox tests/integration/sandbox
5112 passed in 101.47s

$ ruff check src/sandbox tests/unit/sandbox tests/integration/sandbox scripts/docs_tool_catalog.py
All checks passed!

$ mypy src/sandbox/parsers/nmap_parser.py src/sandbox/parsers/__init__.py scripts/docs_tool_catalog.py
Success: no issues found in 3 source files

$ python scripts/tools_sign.py verify --tools-dir config/tools \
                                       --signatures config/tools/SIGNATURES \
                                       --keys-dir config/tools/_keys
verify.ok verified_count=157
```

---

## Risks / out-of-scope

* **Per-tool JSON / text adapters for the §4.17 active tools** (`responder` log → finding extractor, `ntlmrelayx` socket logger → finding extractor, `bloodhound_python` JSON BloodHound dump → finding extractor) are deferred to Cycle 3. The current YAMLs declare `parse_strategy: text_lines` (or `json_object` where the upstream tool already emits JSON), and `dispatch_parse` falls back to a generic line-by-line extractor that emits one INFO finding per non-empty stdout line — sufficient for evidence-tagging today but not for severity-aware classification.
* **`mobsf_api`** requires a deployed MobSF instance (`{api_key}` placeholder is intentionally a deferred secret resolved from Vault at run time) — full e2e exercise lands in Cycle 5 (cluster ops).
* **`playwright_runner`** + **`puppeteer_screens`** runner scripts under `sandbox/scripts/playwright/` are placeholders; the actual JS scenarios + DOM-XSS verifier scripts are tracked under ARG-016 risks (Cycle 3 supply-chain).
* **`responder` / `ntlmrelayx` / `bloodhound_python` end-to-end verification** requires a real-AD lab segment; Cycle 6 will validate against a `vulhub`-equivalent lab.
* **NSE non-`vulners` script output extraction** (smb-vuln-ms17-010, ssl-heartbleed, etc.) — current parser logs at debug + skips. Cycle 3 will add per-script extractors keyed off `<script id>`.
* **CVSS v4 support** — `parse_nmap_xml` currently understands the v3 0.1–10.0 score range. Vulners DB has not yet emitted v4-scored rows in production traffic; we will revisit when the upstream changes land.
* **Pre-existing repo-wide test issues** — three test modules (`test_argus010_sse_observability.py`, `test_fix_004_cost_tracking.py`, `test_fix_006_recon.py`) fail at collection time due to unrelated `SQLAlchemy` engine-arg drift and missing internal symbols, and the `payloads` + `prompts` registries trip 3 170 signature-verification errors because the YAMLs and `SIGNATURES` files in `backend/config/payloads/` and `backend/config/prompts/` are out of sync. None of these touch the tool catalog or ARG-019; they are out of scope.

---

## Backlog DoD impact

* **§19.6 (catalog ≥ 150):** **CLOSED** — catalog stands at 157 signed YAMLs.
* **§4.17 / §4.18 / §4.19:** **CLOSED** — every entry is signed, validated, and exercised by the semantic + integration suites.
* **§4.2 (Nmap back-port):** **CLOSED** — all five Cycle 1 Nmap tools now emit findings end-to-end through `dispatch_parse(ParseStrategy.XML_NMAP, ..., tool_id=...)` instead of the silent no-op of Cycle 1.
* **ARG-020 unblocked:** the capstone task can now wire `state_machine` against the closed catalog.
