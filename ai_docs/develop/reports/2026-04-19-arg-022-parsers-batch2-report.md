# ARG-022 — Per-tool parsers batch 2 (TEXT_LINES Network/Auth/Post-exploit) — Completion Report

- **Cycle:** 3 (Finalisation cycle 3 / `2026-04-19-argus-finalization-cycle3.md`).
- **Backlog reference:** §4.2 (Active recon) + §4.12 (Auth/brute) + §4.17 (Network protocol / AD/SMB/SNMP/LDAP) + §11 (Evidence pipeline + redaction) + §19.1 (Coverage matrix).
- **Owner:** worker (Cycle 3 batch 2).
- **Completed:** 2026-04-19.
- **Status:** Completed — all 10 tools wired, all acceptance criteria met, critical hash-redaction guardrail enforced for `impacket_secretsdump`, no regressions in adjacent dispatch suites.

---

## 1. Summary

ARG-022 closes the second-largest heartbeat gap in the cycle-2 catalog: the
ten flagship Active Directory / SMB / SNMP / LDAP / post-exploitation
tools that already shipped YAML descriptors but routed to the
`ARGUS-HEARTBEAT` fallback because no per-tool parser was wired into
`src.sandbox.parsers._DEFAULT_TOOL_PARSERS`.

After ARG-022 the per-tool dispatch table grows from **43 → 53** mapped
parsers; the heartbeat fallback drops from **114 → 104** descriptors.
Every new parser is a pure
`(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]` function,
follows the `bandit_parser` / `interactsh_parser` template established
by ARG-021, and emits a tool-tagged JSONL evidence sidecar so multiple
tools can share an `/out` directory without overwriting each other.

The single most security-critical control — `impacket_secretsdump`
NT/LM/AES hash redaction — is enforced by a dedicated integration test
(`test_impacket_secretsdump_redacts_hashes_in_sidecar`) backed by both a
**LM:NT pair** regex (`[a-fA-F0-9]{32}:[a-fA-F0-9]{32}`) and a **lone
≥32-hex blob** regex (which catches SHA-1, SHA-256, AES key, and
Kerberos blob leaks). Both regexes return **0 hits** on the canonical
NTDS.dit fixture; the `[REDACTED-NT-HASH]` marker is asserted present.

---

## 2. Headline metrics

| Metric                                                                                                                | Before        | After         | Δ                |
| --------------------------------------------------------------------------------------------------------------------- | ------------- | ------------- | ---------------- |
| Mapped per-tool parsers                                                                                               | 43            | **53**        | **+10 (+23 %)**  |
| Heartbeat fallback descriptors                                                                                        | 114           | **104**       | **-10**          |
| Binary-blob descriptors                                                                                               | 0             | 0             | 0                |
| Catalog total descriptors                                                                                             | 157           | 157           | 0                |
| New parser modules                                                                                                    | —             | 10            | +10              |
| New shared helper modules                                                                                             | —             | 1 (`_text_base.py`) | +1         |
| New unit-test files                                                                                                   | —             | 11            | +11              |
| New unit-test cases                                                                                                   | —             | 122 ¹         | +122             |
| New integration-test cases (`test_arg022_dispatch.py`)                                                                | —             | 53            | +53              |
| Realistic fixtures                                                                                                    | —             | 10            | +10              |
| Sandbox + catalog test surface (`tests/unit/sandbox/parsers + tests/integration/sandbox/parsers + tests/test_tool_catalog_coverage.py`) | 2630          | **2805**      | +175             |
| Coverage of new parser modules (per-module floor)                                                                     | —             | 92 %          | floor            |
| Coverage of new parser modules (TOTAL across 11 modules)                                                              | —             | **95 %**      | well above 90 %  |
| `mypy --strict` on 11 new files (10 parsers + 1 helper)                                                               | —             | **clean**     | 0 errors         |
| `ruff check + format` on 25 new/modified files                                                                        | —             | **clean**     | 0 errors         |
| Raw NT/LM/AES hash bytes leaked through `impacket_secretsdump` sidecar                                                | n/a           | **0**         | enforced         |
| Default SNMP community detected via `snmpwalk` parser (CWE-256)                                                       | not detected  | first-class   | new severity     |

¹ 18 cases on the shared helper (`test_text_base.py`) + 11 cases on
`impacket_secretsdump_parser` (security-critical, +1 over the bar) +
93 cases across the 9 remaining parsers (≥10 each, so up to +30 over
the ≥6 acceptance bar). Exact counts are pinned in the per-suite
collection report.

---

## 3. Tools wired (10)

Every tool is registered against its YAML-declared `parse_strategy` in
`src.sandbox.parsers._DEFAULT_TOOL_PARSERS`:

| `tool_id`               | Family                       | YAML strategy   | Source shape                                  | Severity / CWE                                            | Special handling                                                                                  |
| ----------------------- | ---------------------------- | --------------- | --------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `impacket_secretsdump`  | AD post-exploit (NTDS.dit)   | `text_lines`    | `domain\user:rid:LM:NT:::` rows               | `high`, CWE-522 + CWE-200, AUTH                           | **CRITICAL** — `LM`/`NT`/`AES`/Kerberos blobs replaced by `[REDACTED-NT-HASH]` BEFORE FindingDTO construction. Multiple credential families: NTDS users, machine accounts, cleartext, AES keys, Kerberos. |
| `evil_winrm`            | WinRM post-exploit shell     | `text_lines`    | Interactive PS session log                    | `info`, CWE-77, POST_EXPLOITATION                         | Captures session host, last command, exit-code marker, remote errors. One marker finding per session. |
| `kerbrute`              | Kerberos username enum       | `text_lines`    | `[+] VALID USERNAME: <user>@<realm>` lines     | `high`, CWE-200 + CWE-203, AUTH                           | AS-REP roastable accounts (`[!] AS-REP roastable: ...`) emit a separate higher-confidence finding. |
| `bloodhound_python`     | AD graph collector           | `text_lines`    | `INFO Dumped X.zip` / `[+] Found N domains`    | `info`, CWE-200, RECON                                    | One finding per ZIP marker (path captured) + one per domain enum. Binary BloodHound JSON is deferred. |
| `snmpwalk`              | SNMPv2 OID walk              | `text_lines`    | `OID = TYPE: VALUE` lines                      | `info` for sys*, **`high` for default community (CWE-256)** | Detects `community public` / `private` and routes to a dedicated `default-community` finding.       |
| `ldapsearch`            | LDIF directory enum          | `text_lines`    | LDIF blocks (`dn:`, `objectClass:`, `memberOf:`) | `low` for plain accounts, `medium` for privileged groups | Privileged-group detection (`Domain Admins`, `Enterprise Admins`, etc.) raises severity. Hash-shaped attribute values are routed through `redact_hash_string`. |
| `smbclient`             | SMB share listing            | `text_lines`    | `\\HOST\SHARE   Disk   Comment` rows           | `low` (enum) / `medium` (admin shares)                    | Distinguishes administrative shares (`ADMIN$`, `C$`, `IPC$`) from user-defined shares.            |
| `smbmap`                | SMB access-rights matrix     | `text_lines`    | `[+] IP:PORT Name:HOSTNAME` + share rows       | `low` → `high` based on rights                            | `READ ONLY` → low; `READ, WRITE` → medium; `NO ACCESS` → info. World-writable share detection.    |
| `enum4linux_ng`         | Legacy enum4linux text path  | `json_object` ² | `=== <section> ===` headers + `key = value`     | `low`, CWE-200, RECON                                     | Null-session indicators (`Sharing OK with empty credentials`) raise severity. JSON path explicitly out of scope per task. |
| `rpcclient_enum`        | Null-session RPC enum        | `text_lines`    | `user:[NAME] rid:[0xRID]` blocks               | `low`, CWE-200, RECON                                     | Domain users / groups / domain summary / null-session indicators each surface as a finding.       |

² `enum4linux_ng.yaml` declares `parse_strategy=json_object` because
the upstream tool offers `-oJ`. This task explicitly scopes the
**legacy text path** (per ARG-022 acceptance criteria), so the parser
is registered against the `JSON_OBJECT` strategy and operates on the
plain-text stdout that the YAML's `command_template` produces by
default. The integration test routes the fixture via
`ParseStrategy.JSON_OBJECT` to mirror real dispatch.

All ten parsers share a single house style:

```
_normalise_severity → _classify_category → _make_finding
                                              ↓
                                       _emit_with_dedup → JSONL sidecar
```

Every parser is fail-soft: malformed records emit a structured
`parser.malformed_record` `WARNING` and are skipped without aborting
the dispatch loop.

---

## 4. Implementation details

### 4.1 Shared helper (`src/sandbox/parsers/_text_base.py`)

A new common module isolates text-line tokenisation and the
hash-redaction surface so the security-critical regexes are auditable
in one place.

| Helper                                            | Purpose                                                                                                      |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `parse_kv_lines(text, sep="=")`                   | Yields `(key, value)` pairs, trims whitespace, skips empty lines and lines without the separator.           |
| `extract_regex_findings(text, patterns)`          | Yields `(pattern_name, re.Match)` per match across an ordered `dict[str, re.Pattern[str]]`.                  |
| `redact_hash_string(value)`                       | Pure string transform: replaces LM:NT pairs with `[REDACTED-NT-HASH]`, lone NT/SHA-1/SHA-256/AES blobs with `[REDACTED-HASH]`, Kerberos `$krb5tgs$` / `$krb5asrep$` / `$krb5pa$` blobs with `[REDACTED-KRB-HASH]`. |
| `redact_hashes_in_evidence(evidence)`             | Returns a NEW `dict[str, str]` with `redact_hash_string` applied to every value; never mutates the input.    |

All four functions are pure (no I/O, no global state) and have 100 %
unit-test coverage (18 cases in `test_text_base.py`, including
"already-redacted strings stay stable" and "input dict is not
mutated").

### 4.2 Parser modules

Each parser lives at
`backend/src/sandbox/parsers/<tool>_parser.py` and exposes:

* `parse_<tool>(stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str) -> list[FindingDTO]`
* `EVIDENCE_SIDECAR_NAME: Final[str] = "<tool>_findings.jsonl"`

The 10 sidecar filenames are pinned-unique (asserted by
`test_arg022_tools_use_distinct_sidecar_filenames`) so a single
artifacts directory can hold the JSONL evidence of the entire batch
without overwrites — verified end-to-end by
`test_all_arg022_parsers_in_single_artifacts_dir_keeps_sidecars_intact`.

### 4.3 Dispatch wiring (`src/sandbox/parsers/__init__.py`)

`_DEFAULT_TOOL_PARSERS` grew by 10 entries (annotated with `ARG-022`
+ Backlog §4.2/§4.12/§4.17 references). Every existing registration
(httpx, ffuf_dir, katana, wpscan, nuclei, nikto, wapiti, trivy_image,
trivy_fs, semgrep, sqlmap_safe, dalfox, interactsh_client, nmap_*,
bandit, gitleaks, kube_bench, checkov, kics, terrascan, tfsec, dockle,
mobsf_api, grype) is preserved — verified by
`test_arg022_does_not_drop_prior_cycle_registrations`.

### 4.4 Tests

* **Unit (`tests/unit/sandbox/parsers/test_<tool>_parser.py`)** —
  122 tests across 11 suites (10 parsers + the new helper). Every
  per-parser suite covers: empty input, happy path, malformed lines,
  severity edge cases, dedup behaviour, sidecar emission. Two
  parsers carry extra suites: `_text_base` (18 cases — helper
  pre-condition), `impacket_secretsdump` (11 cases — the security gate
  has its own dedicated unit-level redaction case in addition to the
  integration guardrail).
* **Integration (`tests/integration/sandbox/parsers/test_arg022_dispatch.py`)**
  — 53 cases organised as:
  * 10 × tool-registration sanity (`test_arg022_tool_is_registered`),
  * `test_arg022_does_not_drop_prior_cycle_registrations`,
  * `test_registered_count_is_53` (hard ratchet),
  * 10 × happy-path dispatch (`test_dispatch_routes_each_arg022_tool`),
  * 10 × dispatch+sidecar tagging (`test_dispatch_writes_per_tool_sidecar`),
  * `test_arg022_tools_use_distinct_sidecar_filenames`,
  * **`test_impacket_secretsdump_redacts_hashes_in_sidecar`** (security
    gate),
  * 7 × cross-routing inertness pairs (defence in depth),
  * 10 × determinism pairs (`test_arg022_dispatch_is_deterministic`),
  * `test_all_arg022_parsers_in_single_artifacts_dir_keeps_sidecars_intact`,
  * `test_heartbeat_fallback_for_unmapped_tool_id`.
* **`tests/test_tool_catalog_coverage.py`** — augmented with two
  pinned constants and a new ratchet test
  (`test_parser_coverage_counts_match_arg022_ratchet`):
  * `MAPPED_PARSER_COUNT = 53`
  * `HEARTBEAT_PARSER_COUNT = 104`
  Drift in either direction (parser regression OR mapped+1 without
  heartbeat–1) fails CI loudly.

### 4.5 Fixtures

10 realistic fixtures, one per tool, live under
`backend/tests/fixtures/sandbox_outputs/<tool>/sample.txt`. Each
contains ≥10 lines of realistic upstream output, including:

* `impacket_secretsdump` — 5 NTDS principals + machine account + cleartext + AES key + Kerberos blob (covers every redaction codepath).
* `kerbrute` — valid users, AS-REP roastable accounts, and lock-out warnings.
* `snmpwalk` — `sysDescr` / `sysContact` / **`community public`** trigger.
* `ldapsearch` — three LDIF blocks including a Domain-Admins-bearing privileged-account block.
* `smbmap` — mixed `READ ONLY` / `READ, WRITE` / `NO ACCESS` rights matrix.
* `enum4linux_ng` — three `=== <section> ===` headers + null-session indicator.
* `rpcclient_enum` — domain users + groups + domain summary + null-session indicator.

Fixture re-use across unit + integration suites means fixture drift
cannot silently break either layer.

### 4.6 Documentation

`docs/tool-catalog.md` regenerated via
`python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md`.
Re-run with `--check` confirms zero drift. The "Parser coverage"
section now reports:

```
| **`mapped`**      | 53  | 33.76% |
| **`heartbeat`**   | 104 | 66.24% |
| **`binary_blob`** | 0   |  0.00% |
| **Total**         | 157 | 100.00% |
```

---

## 5. Verification

| Check                                                                    | Command                                                                                                                                       | Result            |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| ARG-022 parser modules + helper type-check                               | `python -m mypy --strict src/sandbox/parsers/_text_base.py src/sandbox/parsers/{impacket_secretsdump,evil_winrm,kerbrute,bloodhound_python,snmpwalk,ldapsearch,smbclient_check,smbmap,enum4linux_ng,rpcclient_enum}_parser.py` | **clean** (11 files) ³ |
| ARG-022 lint                                                             | `python -m ruff check src/sandbox/parsers/{_text_base,...} src/sandbox/parsers/__init__.py tests/unit/sandbox/parsers/test_{...}.py tests/integration/sandbox/parsers/test_arg022_dispatch.py tests/test_tool_catalog_coverage.py` | **clean** (25 files) |
| ARG-022 format check                                                     | `python -m ruff format --check ...` (same 25 files)                                                                                            | **clean**         |
| Per-parser unit tests (11 suites)                                        | `python -m pytest tests/unit/sandbox/parsers/test_{text_base,impacket_secretsdump,evil_winrm,kerbrute,bloodhound_python,snmpwalk,ldapsearch,smbclient_check,smbmap,enum4linux_ng,rpcclient_enum}_parser.py` | **122 passed**    |
| ARG-022 integration suite                                                | `python -m pytest tests/integration/sandbox/parsers/test_arg022_dispatch.py`                                                                  | **53 passed**     |
| Heartbeat fallback unaffected                                            | `python -m pytest tests/integration/sandbox/parsers/test_heartbeat_finding.py`                                                                | **8 passed**      |
| ARG-021 dispatch suite unaffected                                        | `python -m pytest tests/integration/sandbox/parsers/test_arg021_dispatch.py`                                                                  | included in below |
| Coverage matrix gate (incl. new ratchet test)                            | `python -m pytest tests/test_tool_catalog_coverage.py`                                                                                         | clean             |
| Aggregated sandbox parser surface + catalog coverage                     | `python -m pytest tests/unit/sandbox/parsers tests/integration/sandbox/parsers tests/test_tool_catalog_coverage.py`                            | **2805 passed**   |
| Per-module coverage (every ARG-022 module ≥ 90 %)                        | `python -m pytest --cov=src.sandbox.parsers.{_text_base,...} --cov-report=term-missing tests/unit/sandbox/parsers tests/integration/sandbox/parsers/test_arg022_dispatch.py` | **95 % TOTAL**    |
| Docs in-sync drift guard                                                 | `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md` then `git diff --quiet docs/tool-catalog.md`                              | clean             |

³ Two pre-existing `mypy` errors in `src/sandbox/network_policies.py`
(`subnet_of` argument type narrowing for `IPv4Network | IPv6Network`)
surface as transitive errors when `mypy` follows imports from the
parser stack. They are **not** introduced by ARG-022 (verified by
git status — `network_policies.py` is untouched in this branch) and
are scheduled for fix in a dedicated tech-debt task. Filtering the
`mypy` output by ARG-022 file paths returns **0 errors**.

### 5.1 Per-module coverage

```
src/sandbox/parsers/_text_base.py                       100 %
src/sandbox/parsers/bloodhound_python_parser.py          93 %
src/sandbox/parsers/enum4linux_ng_parser.py              97 %
src/sandbox/parsers/evil_winrm_parser.py                 95 %
src/sandbox/parsers/impacket_secretsdump_parser.py       95 %
src/sandbox/parsers/kerbrute_parser.py                   93 %
src/sandbox/parsers/ldapsearch_parser.py                 94 %
src/sandbox/parsers/rpcclient_enum_parser.py             96 %
src/sandbox/parsers/smbclient_check_parser.py            94 %
src/sandbox/parsers/smbmap_parser.py                     96 %
src/sandbox/parsers/snmpwalk_parser.py                   92 %
----------------------------------------------------------------
TOTAL (1135 stmts, 60 missed)                            95 %
```

All 11 modules clear the ≥ 90 % per-module floor required by the plan;
TOTAL 95 % is the consolidated number across the new surface.

---

## 6. Security guardrails

* **`impacket_secretsdump` hash redaction (CRITICAL).** Three layers
  of defence:
  1. **Pure helper layer** (`_text_base.redact_hash_string`) — single
     auditable surface for LM:NT, lone NT, SHA-1, SHA-256, AES, and
     Kerberos blob patterns. Validated by 18 helper-only unit tests.
  2. **Parser layer** — `parse_impacket_secretsdump` calls
     `redact_hashes_in_evidence(...)` BEFORE constructing any
     `FindingDTO`, so the redacted value is the only form that ever
     enters the `evidence` dict. Validated by 11 parser-only unit
     tests including a dedicated "raw hash never reaches FindingDTO"
     case.
  3. **Integration layer** —
     `test_impacket_secretsdump_redacts_hashes_in_sidecar` runs the
     canonical NTDS.dit fixture through `dispatch_parse` and asserts
     two regexes return **0 hits** on the resulting JSONL sidecar:
     * `\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b` — LM:NT pair
     * `\b[a-fA-F0-9]{32,}\b`                 — any lone ≥32-hex blob
     plus a positive assertion that the canonical
     `[REDACTED-NT-HASH]` marker IS present.

  This three-layer scheme means a regression at any layer is caught
  by tests above and below, not just at one level — defence in depth
  for the platform's most sensitive evidence type.

* **`snmpwalk` default-community detection (CWE-256).** `community
  public` and `community private` lines route to a dedicated `high`
  finding rather than blending into the `info`-bucket of generic
  sys*-disclosure findings. This makes default-community misconfiguration
  show up as a top-of-report finding instead of being buried under
  benign SNMP noise.

* **`ldapsearch` privileged-group detection.** Memberships in
  `Domain Admins`, `Enterprise Admins`, `Schema Admins`, and similar
  high-privilege groups raise the per-account finding's confidence /
  severity. Hash-shaped attribute values (e.g.
  `unicodePwd`) are routed through `redact_hash_string` so any
  upstream LDIF that surfaces a credential blob is masked.

* **Defensive parsing across all 10 tools.** Every parser uses
  `safe_decode` + per-record `try/except` + structured
  `WARNING parser.malformed_record` log. A malformed input slice
  never crashes the dispatch loop and never silently swallows the
  scan; it logs once and produces zero findings for the bad slice.

* **No CWE / CVSS / severity hard-coding outside the parser.** All
  per-tool mapping tables are local module constants, easy to audit
  in a single grep, and unit-tested with ≥ 6 cases per parser
  (≥ 10 in practice for half of them).

* **Cross-tool routing isolation.** 7 cross-routing pairs
  (`kerbrute↔smbmap`, `smbmap↔kerbrute`, `ldapsearch↔snmpwalk`,
  `snmpwalk↔ldapsearch`, `rpcclient_enum↔smbclient`,
  `evil_winrm↔bloodhound_python`, `impacket_secretsdump↔evil_winrm`)
  prove that pushing payload from tool A through tool B's `tool_id`
  yields `[]`, never partial / corrupted FindingDTOs. The
  `impacket↔evil_winrm` pair is intentional: both parsers see hash-shaped
  hex strings on stdout and would be the natural shape-confusion attack
  surface.

---

## 7. Non-regression

* **Prior cycle parser surface intact.** Verified by
  `test_arg022_does_not_drop_prior_cycle_registrations` (24 prior-cycle
  tools enumerated and asserted present).
* **Prior cycle dispatch suites green.**
  `test_arg021_dispatch.py` (35 cases), `test_dispatch_registry.py`,
  `test_ffuf_dispatch.py`, `test_interactsh_dispatch.py`,
  `test_katana_dispatch.py`, `test_nmap_dispatch.py`,
  `test_nuclei_dispatch.py`, `test_trivy_semgrep_dispatch.py`,
  `test_wpscan_dispatch.py` — all pass.
* **Heartbeat fallback contract intact.**
  `tests/integration/sandbox/parsers/test_heartbeat_finding.py` — 8 cases
  pass; an unmapped `tool_id` over a known strategy still produces
  exactly one `HEARTBEAT-{tool_id}` `FindingDTO` with
  `cvss_v3_score=0.0`.
* **Total descriptors held at 157.** Catalog YAML/SIGNATURES
  untouched by this batch (verified by `git status backend/config/tools/`
  showing no `M` entries on the tracked SIGNATURES file ⁴).
* **`docs/tool-catalog.md` `--check` mode passes** — committed doc is
  in sync with the regenerated output.

⁴ During the verification cycle a `git stash --include-untracked`
operation triggered `.gitattributes` smudge filters
(`* text=auto eol=lf`) that normalised line endings on 80 of the 157
untracked YAML descriptors, breaking their pre-computed sha256s in
SIGNATURES. The original CRLF byte-perfect form was restored
automatically (LF→CRLF round-trip — sha256s confirmed identical post-
restoration), no YAML content was modified, and SIGNATURES was not
re-signed. This is captured here purely for traceability; the
acceptance bar "no modification to existing tool YAMLs" was met.

---

## 8. Known gaps (carry-over to ARG-029 / ARG-030)

ARG-022 intentionally focused on the §4.2/§4.12/§4.17 TEXT_LINES
cluster; the following remain on heartbeat fallback and are owned by
subsequent batches:

* **§4.7 OAST + §4.14 API/GraphQL + §4.15/§4.16 cloud/secrets cluster
  (deferred to ARG-029):** `trufflehog`, `naabu`, `masscan`, `prowler`,
  `detect_secrets`, `openapi_scanner`, `graphql_cop`, `postman_newman`,
  `zap_baseline`, `syft`, `cloudsploit`, `hashid`, `hash_analyzer`,
  `jarm`, `wappalyzer_cli` (15 tools).
* **`bloodhound_python` binary BloodHound JSON ZIP body** is still
  out of scope (ARG-022 captures only the collector log + ZIP creation
  marker); a dedicated parser for the in-ZIP JSON lives in the Cycle 4
  follow-up.
* **`enum4linux_ng` JSON path (`-oJ`)** is out of scope — the YAML
  declares `parse_strategy=json_object` but the parser handles the
  legacy text path per ARG-022 acceptance criteria.

After ARG-029 the catalog should reach ≥ 68 / 157 mapped (target ≤ 89
heartbeat) per Cycle 3 plan. ARG-030 (CAPSTONE) will add contracts
C11-parser-determinism and C12-evidence-redaction-completeness so the
ratchet test in `tests/test_tool_catalog_coverage.py` is covered by an
explicit determinism + redaction integration matrix.

---

## 9. Files changed

```
backend/src/sandbox/parsers/_text_base.py                                 (new — shared text-line + hash-redaction helpers, 100% coverage)
backend/src/sandbox/parsers/impacket_secretsdump_parser.py                (new — CRITICAL hash redaction)
backend/src/sandbox/parsers/evil_winrm_parser.py                          (new)
backend/src/sandbox/parsers/kerbrute_parser.py                            (new)
backend/src/sandbox/parsers/bloodhound_python_parser.py                   (new)
backend/src/sandbox/parsers/snmpwalk_parser.py                            (new — default-community detection)
backend/src/sandbox/parsers/ldapsearch_parser.py                          (new — privileged-group detection)
backend/src/sandbox/parsers/smbclient_check_parser.py                     (new)
backend/src/sandbox/parsers/smbmap_parser.py                              (new)
backend/src/sandbox/parsers/enum4linux_ng_parser.py                       (new — legacy text path)
backend/src/sandbox/parsers/rpcclient_enum_parser.py                      (new)
backend/src/sandbox/parsers/__init__.py                                   (modify: +10 imports + 10 dispatch entries + ARG-022 docstring block)
backend/tests/fixtures/sandbox_outputs/impacket_secretsdump/sample.txt    (new)
backend/tests/fixtures/sandbox_outputs/evil_winrm/sample.txt              (new)
backend/tests/fixtures/sandbox_outputs/kerbrute/sample.txt                (new)
backend/tests/fixtures/sandbox_outputs/bloodhound_python/sample.txt       (new)
backend/tests/fixtures/sandbox_outputs/snmpwalk/sample.txt                (new)
backend/tests/fixtures/sandbox_outputs/ldapsearch/sample.txt              (new)
backend/tests/fixtures/sandbox_outputs/smbclient/sample.txt               (new)
backend/tests/fixtures/sandbox_outputs/smbmap/sample.txt                  (new)
backend/tests/fixtures/sandbox_outputs/enum4linux_ng/sample.txt           (new)
backend/tests/fixtures/sandbox_outputs/rpcclient_enum/sample.txt          (new)
backend/tests/unit/sandbox/parsers/test_text_base.py                      (new — 18 cases, 100% coverage of helper)
backend/tests/unit/sandbox/parsers/test_impacket_secretsdump_parser.py    (new — 11 cases incl. hash redaction)
backend/tests/unit/sandbox/parsers/test_evil_winrm_parser.py              (new — 10 cases)
backend/tests/unit/sandbox/parsers/test_kerbrute_parser.py                (new — 10 cases)
backend/tests/unit/sandbox/parsers/test_bloodhound_python_parser.py       (new — 10 cases)
backend/tests/unit/sandbox/parsers/test_snmpwalk_parser.py                (new — 10 cases)
backend/tests/unit/sandbox/parsers/test_ldapsearch_parser.py              (new — 11 cases incl. hash redaction)
backend/tests/unit/sandbox/parsers/test_smbclient_check_parser.py         (new — 10 cases)
backend/tests/unit/sandbox/parsers/test_smbmap_parser.py                  (new — 11 cases)
backend/tests/unit/sandbox/parsers/test_enum4linux_ng_parser.py           (new — 10 cases)
backend/tests/unit/sandbox/parsers/test_rpcclient_enum_parser.py          (new — 11 cases)
backend/tests/integration/sandbox/parsers/test_arg022_dispatch.py         (new — 53 cases incl. impacket redaction guardrail + 7-pair cross-routing)
backend/tests/test_tool_catalog_coverage.py                               (modify: +MAPPED_PARSER_COUNT/HEARTBEAT_PARSER_COUNT constants + test_parser_coverage_counts_match_arg022_ratchet)
docs/tool-catalog.md                                                      (regenerated; mapped=53, heartbeat=104, binary_blob=0)
ai_docs/develop/reports/2026-04-19-arg-022-parsers-batch2-report.md       (new — this file)
.cursor/workspace/active/orch-2026-04-19-argus-cycle3/tasks.json          (modify: ARG-022 status → completed)
CHANGELOG.md                                                              (modify: +ARG-022 section under [Unreleased])
```

---

## 10. Sign-off

ARG-022 — Per-tool parsers batch 2 (TEXT_LINES Network/Auth/Post-exploit, 10) —
**Completed** on 2026-04-19. Mapped parser count grew from 43 → 53
(+23 %); heartbeat fallback dropped from 114 → 104 (–9 %). All
acceptance criteria met, no regressions in adjacent dispatch suites,
`impacket_secretsdump` hash redaction enforced by a three-layer
guardrail (helper unit tests + parser unit test + integration sidecar
regex check). The pinned `MAPPED_PARSER_COUNT = 53` /
`HEARTBEAT_PARSER_COUNT = 104` ratchet in `test_tool_catalog_coverage.py`
makes any future drift loud.

Ready for hand-off to ARG-029 (parsers batch 3 — JSON_LINES + custom +
mixed JSON_OBJECT, 15 tools) and ARG-030 (CAPSTONE coverage matrix +
Cycle 3 sign-off report).
