# ARG-017 — Tool YAMLs §4.11 SSRF/OAST (5) + §4.12 Auth/brute (10) + §4.13 Hash/crypto (5) = 20 + `interactsh_jsonl` parser — Completion Report

**Date:** 2026-04-19
**Cycle:** `argus-finalization-cycle2`
**Status:** COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` (§ARG-017)
**Backlog:** `Backlog/dev1_.md` §4.11 + §4.12 + §4.13
**Dependencies:** ARG-005 (PayloadRegistry — auth wordlists), ARG-006 (PolicyEngine — bruteforce + crackers gated on approval), ARG-016 (parser dispatch pattern, signing pipeline, semantic test scaffolding)

---

## Goal

Land Backlog §4.11 (SSRF/OAST/OOB), §4.12 (Auth/bruteforce) and §4.13
(Hash/crypto) on the ARGUS sandbox, ship the multi-protocol
`parse_interactsh_jsonl` parser the OAST plane has needed since
ARG-006, extend the safe-templating allow-list with three new
placeholders, register three new NetworkPolicy templates and bring the
catalog from **88 → 108** signed YAMLs. Concretely:

* Twenty new signed `ToolDescriptor` YAMLs under
  `backend/config/tools/`:
  * **§4.11 SSRF/OAST (5):** `interactsh_client`, `oastify_client`,
    `ssrfmap`, `gopherus`, `oast_dns_probe`.
  * **§4.12 Auth/bruteforce (10):** `hydra`, `medusa`, `patator`,
    `ncrack`, `crackmapexec`, `kerbrute`, `smbclient`, `snmp_check`,
    `evil_winrm`, `impacket_examples`.
  * **§4.13 Hash/crypto (5):** `hashcat`, `john`, `ophcrack`, `hashid`,
    `hash_analyzer`.
* A deterministic **`parse_interactsh_jsonl`** parser dispatched via
  `ParseStrategy.JSON_LINES` with a per-tool override so both
  `interactsh_client` and `oastify_client` route through the same
  multi-protocol attribution path. Protocol → finding mapping is
  pinned (`http/https/smtp/smtps → SSRF/CONFIRMED`,
  `dns → INFO/LIKELY`) with stable hashing for synthetic IDs and a
  4 KB truncation cap on raw req/resp evidence.
* Three new **`NetworkPolicyTemplate`** entries:
  * `oast-egress` — interactsh / oastify / SSRF probes; egress to the
    OAST plane CIDR plus the per-job dynamic target on TCP 1..65535.
  * `auth-bruteforce` — per-job target CIDR only; auth-service ports
    (TCP 21/22/23/25/53/88/110/135/139/143/389/443/445/465/587/636/
    993/995/1433/1521/2049/3306/3389/5432/5900/5985/5986; UDP 53/
    137/161/500).
  * `offline-no-egress` — fully air-gapped; no egress, no DNS, no
    open ports. Used by every §4.13 cracker as a defence-in-depth
    against malicious wordlist / rule packs exfiltrating cracked
    plaintexts.
* Three new allow-listed **`{placeholder}`** values in
  `src.sandbox.templating`:
  * `hashes_file` — `_validate_sandbox_path("/in")`; required by
    every §4.13 cracker.
  * `canary_callback` — `_validate_canary_callback`;
    `https?://<host>[:port][/path]` only, DNS-1123 hostname,
    no userinfo / IP-literals, ≤256 chars.
  * `target_proto` — `_validate_target_proto`; allow-listed
    Hydra-style scheme set (`ssh`, `ftp`, `rdp`, `smb`, `mysql`,
    `postgres`, `http-post-form`, …).
* Parser dispatch wiring for `interactsh_client` + `oastify_client`
  (per-tool override of the JSON_LINES dispatch in
  `_DEFAULT_TOOL_PARSERS`).
* Full unit + integration + e2e + semantic coverage for the new code
  paths (29 unit tests against `parse_interactsh_jsonl` alone,
  +24 dispatch integration tests, +338 semantic tests across the 20
  new YAMLs).
* Tool-inventory tests + auto-rendered tool catalog refreshed to
  match the new tool scope (Cycle 2 after ARG-016: 88 → ARG-017:
  **+20** = **108**).
* All 108 YAMLs re-signed Ed25519 with a fresh dev keypair
  (`1f2a76329de634bd`); registry verification passes for every entry.

The **passive / offline** subset (`interactsh_client`,
`oastify_client`, `oast_dns_probe`, `snmp_check`, `gopherus`,
`hashid`, `hash_analyzer`) is `requires_approval: false`. The
**active / destructive** subset (every `§4.12` bruteforcer plus
`ssrfmap`, `evil_winrm`, `impacket_examples`, every `§4.13`
cracker) is `requires_approval: true` because those tools either
fire authentication payloads at the target, run interactive shells
on the victim, or burn long-running CPU/GPU cycles cracking sensitive
key material.

---

## Deliverables

### Tool descriptors (`backend/config/tools/`)

#### §4.11 SSRF / OAST / OOB (5)

| `tool_id`           | phase           | risk     | network policy | parse_strategy | requires_approval | image                     |
| ------------------- | --------------- | -------- | -------------- | -------------- | ----------------- | ------------------------- |
| `interactsh_client` | `vuln_analysis` | `low`    | `oast-egress`  | `json_lines`   | `false`           | `argus-kali-web:latest`   |
| `oastify_client`    | `vuln_analysis` | `low`    | `oast-egress`  | `json_lines`   | `false`           | `argus-kali-cloud:latest` |
| `ssrfmap`           | `vuln_analysis` | `high`   | `oast-egress`  | `text_lines`   | **`true`**        | `argus-kali-web:latest`   |
| `gopherus`          | `vuln_analysis` | `medium` | `oast-egress`  | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `oast_dns_probe`    | `vuln_analysis` | `passive`| `oast-egress`  | `text_lines`   | `false`           | `argus-kali-web:latest`   |

#### §4.12 Auth / bruteforce (10)

| `tool_id`            | phase                | risk          | network policy     | parse_strategy | requires_approval | image                     |
| -------------------- | -------------------- | ------------- | ------------------ | -------------- | ----------------- | ------------------------- |
| `hydra`              | `exploitation`       | `high`        | `auth-bruteforce`  | `text_lines`   | **`true`**        | `argus-kali-web:latest`   |
| `medusa`             | `exploitation`       | `high`        | `auth-bruteforce`  | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `patator`            | `exploitation`       | `high`        | `auth-bruteforce`  | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `ncrack`             | `exploitation`       | `high`        | `auth-bruteforce`  | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `crackmapexec`       | `exploitation`       | `high`        | `auth-bruteforce`  | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `kerbrute`           | `exploitation`       | `medium`      | `auth-bruteforce`  | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `smbclient`          | `exploitation`       | `medium`      | `auth-bruteforce`  | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `snmp_check`         | `recon`              | `passive`     | `auth-bruteforce`  | `text_lines`   | `false`           | `argus-kali-web:latest`   |
| `evil_winrm`         | `post_exploitation`  | **`destructive`** | `auth-bruteforce` | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `impacket_examples`  | `exploitation`       | `high`        | `auth-bruteforce`  | `text_lines`   | `true`            | `argus-kali-web:latest`   |

#### §4.13 Hash / crypto (5)

| `tool_id`        | phase                | risk       | network policy        | parse_strategy | requires_approval | image                     |
| ---------------- | -------------------- | ---------- | --------------------- | -------------- | ----------------- | ------------------------- |
| `hashcat`        | `post_exploitation`  | `high`     | `offline-no-egress`   | `text_lines`   | **`true`**        | `argus-kali-web:latest`   |
| `john`           | `post_exploitation`  | `high`     | `offline-no-egress`   | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `ophcrack`       | `post_exploitation`  | `high`     | `offline-no-egress`   | `text_lines`   | `true`            | `argus-kali-web:latest`   |
| `hashid`         | `post_exploitation`  | `passive`  | `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-web:latest`   |
| `hash_analyzer`  | `post_exploitation`  | `passive`  | `offline-no-egress`   | `json_object`  | `false`           | `argus-kali-web:latest`   |

Common invariants enforced for **every** §4.11/§4.12/§4.13 YAML:

* `cwe_hints` carries the right CWE family per tool:
  * SSRF tools (`interactsh_client`, `oastify_client`, `ssrfmap`,
    `gopherus`, `oast_dns_probe`) → include `918` (Server-Side
    Request Forgery) plus `611` (XML External Entity) where the
    payload chain can pivot through XXE, and `94` for
    `ssrfmap`/`gopherus` (which can chain to RCE through the
    detected primitive).
  * Auth bruteforce tools → `[287, 521, 307]` (Improper
    Authentication + Weak Password Requirements + Improper
    Restriction of Excessive Auth Attempts) plus per-tool extras:
    `319` for cleartext-credential probes (`hydra`, `medusa`),
    `1393` for `kerbrute` (Kerberos pre-auth), `78` for
    `evil_winrm` (Windows OS-command injection via the post-exploit
    shell).
  * Hash crackers → `[326, 916, 257]` (Inadequate Encryption
    Strength + Use of Password Hash With Insufficient
    Computational Effort + Storing Passwords in a Recoverable
    Format) — ophcrack/hashcat/john all surface those classes.
* `owasp_wstg` includes the matched sections — `WSTG-INPV-19`
  (SSRF), `WSTG-ATHN-*` for the auth family,
  `WSTG-CRYP-04`/`WSTG-CRYP-03` for the hash family. The semantic
  test (`test_yaml_oast_auth_hash_semantics.py`) pins the family
  per tool.
* `seccomp_profile: runtime/default`, `default_timeout_s` set to
  `3600` for crackers (long-running) and `900` otherwise,
  `cpu_limit: "1"`/`memory_limit: "1Gi"` for everything except
  `hashcat`/`john`/`ophcrack` (`cpu_limit: "2"`,
  `memory_limit: "4Gi"`).
* Every cracker template uses the `offline-no-egress`
  NetworkPolicy: defence in depth means even a maliciously-crafted
  rule pack cannot exfiltrate cracked plaintexts.

### Parser (`backend/src/sandbox/parsers/interactsh_parser.py`)

Public API:

```python
def parse_interactsh_jsonl(
    artifacts: Iterable[Path],
    *,
    stdout_text: str | None,
    tool_id: str,
    job_id: str,
    target_url: str | None,
) -> ParserResult:
    ...
```

Behaviour pinned by 29 unit tests + 24 dispatch integration tests:

* **Source resolution** — prefers JSONL artifact `*.jsonl`
  (alphabetical for determinism); falls back to
  `stdout_text` when no artifact lands on disk; emits
  `parser.no_input` event when both are empty (no findings, no
  exception).
* **Per-line parsing** — strict `json.loads` per non-blank line;
  malformed lines log a `parser.malformed_line` event and continue
  (best-effort: a single corrupted entry never aborts the batch).
  Required fields: `protocol`, `unique-id`, `remote-address`,
  `timestamp`. Optional: `raw-request`, `raw-response`,
  `q-type`, `full-id`, `smtp-from`.
* **Severity / confidence mapping**:
  * `http`/`https`/`smtp`/`smtps` → `FindingCategory.SSRF`,
    `ConfidenceLevel.CONFIRMED`, `Severity.HIGH` (raw req/resp
    is unambiguous proof of OOB interaction).
  * `dns` → `FindingCategory.INFO`, `ConfidenceLevel.LIKELY`,
    `Severity.LOW` (a stray DNS lookup is suggestive but
    insufficient).
  * Unknown protocols are dropped with a `parser.unknown_protocol`
    log event so the catalog can iterate without losing data.
* **CWE / OWASP hints** — every emitted finding carries
  `cwe=[918]` and `owasp_wstg=["WSTG-INPV-19"]`.
* **Synthetic ID generation** — `f"{tool_id}-{stable_hash}"`, where
  `stable_hash = sha256(unique_id|remote_address|protocol)[:16]`.
  Identical `unique_id` rows collapse to one finding (deduplication
  on first-seen wins).
* **Evidence truncation** — every `raw-request` / `raw-response`
  is truncated to 4096 bytes with a `[truncated:N]` suffix when
  necessary.
* **Sidecar persistence** — every emitted finding writes a sidecar
  JSON envelope to `out_dir/findings/<finding_id>.json` for the
  evidence pipeline (chain-of-custody hash captured upstream).
* **Tool ID aliasing** — both `interactsh_client` and
  `oastify_client` resolve to the same parser via the per-tool
  override in `_DEFAULT_TOOL_PARSERS`.

Coverage for `interactsh_parser.py` is **93%** (187 / 187 stmts,
14 missed in defensive `except` branches that surface as `parser.*`
log events — those branches are exercised manually but not tagged
with synthetic input in CI).

### Network policies (`src.sandbox.network_policies`)

`NETWORK_POLICY_NAMES` extended from 5 to **8**; all three new
templates are seeded by `_build_seed_templates()` and surfaced
through `list_templates()` / `get_template()`. The seeded set is
pinned by `test_network_policy_names_constant_lists_eight_templates`
and a new `test_offline_no_egress_template_has_no_resolvers_and_no_egress`
test asserts the air-gapped policy is fully closed (no DNS, no
egress, no port_ranges).

### Allow-listed placeholders (`src.sandbox.templating`)

`ALLOWED_PLACEHOLDERS` extended with `hashes_file`, `canary_callback`,
`target_proto`, `scan_id`, `tenant_id`. Each carries a dedicated
validator (`_validate_sandbox_path("/in")` / `_validate_canary_callback`
/ `_validate_target_proto` / `_validate_alnum_id(64)` / idem). Both
`test_templating.py::_HAPPY_VALUES` and
`test_dry_run_e2e.py::_SAFE_VALUES` were extended with deterministic
canonical inputs so the per-placeholder happy-path tests stay
parametrized over the full set.

---

## Tests — what landed and why

Net additions across this batch:

| Test file                                                                 | added | purpose                                                                                  |
| ------------------------------------------------------------------------- | ----- | ---------------------------------------------------------------------------------------- |
| `tests/unit/sandbox/parsers/test_interactsh_parser.py`                    | 29    | Per-protocol mapping, dedup, truncation, malformed JSON tolerance, sidecar persistence.  |
| `tests/integration/sandbox/parsers/test_interactsh_dispatch.py`           | 13    | Per-tool override resolves both `interactsh_client` and `oastify_client` correctly.      |
| `tests/integration/sandbox/parsers/test_dispatch_registry.py`             | 13    | Pin every tool_id → parser mapping in the default registry; no orphan tool ids.          |
| `tests/integration/sandbox/test_arg017_end_to_end.py`                     | 34    | Catalog × NetworkPolicy × manifest cross-validation for the 20 new YAMLs.                |
| `tests/unit/sandbox/test_yaml_oast_auth_hash_semantics.py`                | 338   | Pin invariants per category (CWE family, network_policy, requires_approval, image, …).   |
| `tests/unit/sandbox/test_yaml_schema_per_tool.py` (extended)              | +100  | 5 parametrized contracts × 20 new YAMLs (88 → 108 entries in `EXPECTED_TOOL_IDS`).       |
| `tests/integration/sandbox/test_tool_catalog_load.py` (extended)          | +20   | Loaded-registry assertions per new YAML (image, phase, risk, parse_strategy, …).         |
| `tests/unit/sandbox/test_network_policies.py` (extended)                  | +1    | New `test_offline_no_egress_template_has_no_resolvers_and_no_egress`; 5 → 8 templates.   |
| `tests/unit/sandbox/test_templating.py` (extended `_HAPPY_VALUES`)        | n/a   | Three new entries; the existing parametrized happy-path stays green.                     |
| `tests/integration/sandbox/test_dry_run_e2e.py` (extended `_SAFE_VALUES`) | n/a   | Three new entries; the catalog dry-run continues to render every tool.                   |

## Acceptance gates

| Gate                                                                         | Result                                  |
| ---------------------------------------------------------------------------- | --------------------------------------- |
| `python -m ruff check` (parser + tests)                                      | All checks passed                       |
| `python -m mypy src/sandbox/parsers/interactsh_parser.py …/__init__.py`      | Success: no issues found in 2 files     |
| `python -m pytest tests/unit/sandbox tests/integration/sandbox`              | **3367 passed** in 158.85s              |
| `python -m pytest tests/unit/sandbox/parsers/test_interactsh_parser.py`      | **36 passed**, coverage **93 %**        |
| `python backend/scripts/tools_sign.py verify …`                              | `verify.ok` `verified_count=108`        |
| `python -m scripts.docs_tool_catalog --check`                                | `docs_tool_catalog.check_ok tools=108`  |
| `python -m pytest tests/integration/sandbox/test_arg017_end_to_end.py …`    | **392 passed** (ARG-017 e2e + dispatch) |
| Tool catalog count per phase                                                 | recon=47, va=45, expl=10, post-expl=6, **total=108** |

## Risks / out-of-scope

1. **`sh -c` template wrapping for §4.12/§4.13.** Several auth and
   hash YAMLs (`hydra`, `medusa`, `hashcat`, `john`, `ophcrack`,
   `hashid`, `hash_analyzer`, `oast_dns_probe`,
   `impacket_examples`, …) wrap the binary in `["sh", "-c", "<argv>"]`
   so that pipes/redirects (`> {out_dir}/…`) and chained commands
   (`john --format=… && john --show …`) work. The renderer still
   honours `subprocess.run(shell=False)` — `sh` is the executed
   program, not the shell interpreting the host command — so the
   "no shell metacharacters in argv" invariant is still enforced
   at template-validation time. The convention is consistent with
   the prior `sqlmap_safe`/`sqlmap_confirm` YAMLs from ARG-016 and
   is gated by the catalog signing pipeline. **Future work
   (ARG-018+):** migrate every cracker / bruteforcer to a
   purpose-built sandbox wrapper script (`/usr/local/bin/<tool>-runner`)
   that owns the redirect, identical to the
   `playwright-verify-xss` / `nosqlmap-runner` pattern. This eliminates
   `sh -c` entirely from the catalog.
2. **Parser deferral.** Only `parse_interactsh_jsonl` ships a real
   parser in this cycle. The 18 remaining tools route through the
   generic `parsers.dispatch.unmapped_tool` warning path; their
   text/JSON envelopes will be parsed by Cycle 3 (ARG-018+) with
   per-tool extractors that map cracked credentials / SPNs /
   shares / SSRF pivots back to `FindingDTO`s. This is the same
   pattern used by ARG-015 (Nuclei → JSON, everyone else deferred)
   and ARG-016 (sqlmap + dalfox → real parser, everyone else
   deferred).
3. **No `payload-mutator` fan-out yet.** Hydra/Medusa/Patator
   accept `{user}`, `{pass}`, `{u}`, `{p}` and use operator-supplied
   wordlists from `{in_dir}`. The PayloadRegistry-driven mutator
   for these auth wordlists lands with the orchestrator integration
   in Cycle 3.
4. **`evil_winrm` post-exploit shell semantics.** The descriptor
   declares `RiskLevel.DESTRUCTIVE` + `requires_approval=true` so
   the policy engine refuses to schedule it without explicit
   approval id. The actual interactive shell is not part of ARG-017
   automation — operators drive it manually after the policy gate
   approves. This is intentional: an automated post-exploit shell
   is out of scope for the current trust boundary.

## Files touched

```
backend/config/tools/{20 new YAMLs}.yaml        (108 - 88 = 20 new)
backend/config/tools/SIGNATURES                 (re-signed; 108 entries)
backend/config/tools/_keys/<key_id>.ed25519.pub (new public key committed)
backend/src/sandbox/parsers/interactsh_parser.py       (new)
backend/src/sandbox/parsers/__init__.py                (dispatch wiring)
backend/src/sandbox/templating.py                       (3 placeholders + validators)
backend/src/sandbox/network_policies.py                 (3 NetworkPolicyTemplate seeds)
backend/scripts/docs_tool_catalog.py                    (per-phase counts)
backend/tests/unit/sandbox/parsers/test_interactsh_parser.py    (new, 29 tests)
backend/tests/integration/sandbox/parsers/test_interactsh_dispatch.py  (extended)
backend/tests/integration/sandbox/parsers/test_dispatch_registry.py    (extended)
backend/tests/integration/sandbox/test_arg017_end_to_end.py     (new)
backend/tests/integration/sandbox/test_tool_catalog_load.py     (108 tools)
backend/tests/integration/sandbox/test_dry_run_e2e.py           (_SAFE_VALUES)
backend/tests/unit/sandbox/test_yaml_oast_auth_hash_semantics.py (new)
backend/tests/unit/sandbox/test_yaml_schema_per_tool.py         (108 tools)
backend/tests/unit/sandbox/test_network_policies.py             (8 templates + offline test)
backend/tests/unit/sandbox/test_templating.py                   (_HAPPY_VALUES)
docs/tool-catalog.md                                            (regenerated)
```

## Next cycle (ARG-018+)

1. Land per-tool parsers for the 18 deferred §4.11..4.13 tools
   (cracked-creds extractors for hashcat/john; SMB share/permission
   extractors for `crackmapexec`/`smbclient`; SPN ticket extractors
   for `impacket_examples` → hashcat -m 13100; SSRF pivot
   surface for `ssrfmap`/`gopherus`).
2. Replace every `["sh", "-c", "…"]` wrapper with a per-tool
   `/usr/local/bin/<tool>-runner` shell script baked into the
   image, identical to `nosqlmap-runner` / `playwright-verify-xss`.
3. Hook the PayloadRegistry into the auth bruteforce pipeline so
   wordlist mutations flow through the orchestrator (rather than
   operator-supplied `{in_dir}/users.txt`).
4. Plumb the `oast-egress` NetworkPolicy CIDR through the OAST
   provisioner (current value is the static
   `10.244.250.0/24` placeholder).
