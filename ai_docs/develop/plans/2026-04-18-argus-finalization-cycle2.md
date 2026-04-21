# План: ARGUS v1 — Финализация, Cycle 2 (Catalog §4.4–§4.19 + per-category parsers + state_machine wiring)

**Создан:** 2026-04-18
**Orchestration:** `orch-2026-04-18-argus-cycle2`
**Master plan (источник истины):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md)
**Предыдущий цикл:** [`ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md`](2026-04-17-argus-finalization-cycle1.md) → отчёт [`ai_docs/develop/reports/2026-04-17-argus-finalization-cycle1.md`](../reports/2026-04-17-argus-finalization-cycle1.md)
**Status:** ✅ Closed (2026-04-19) — все 10 задач (ARG-011..ARG-020) выполнены, см. итоговый отчёт `ai_docs/develop/reports/2026-04-19-arg-020-capstone-report.md`.

---

## 1. Цель цикла (Goal)

Закрыть **каталог инструментов** ARGUS до целевого ≥150 (Backlog §19.6) и довести pipeline до **production-reachable** состояния:

1. Доставить **119 tool YAMLs §4.4–§4.19** (HTTP fingerprinting, fuzzing, crawler, CMS, web scanners, SQLi/XSS, SSRF/auth/hash, API/cloud/IaC/code, network/binary/browser) — каждый Pydantic-валидный, Ed25519-подписанный, в каталог-coverage тесте.
2. **Реализовать 10 высокоприоритетных парсеров** (httpx, ffuf, katana, wpscan, nuclei, sqlmap, dalfox, interactsh, trivy, semgrep, nmap_xml) — закрывают `parse_output()`-no-op для самых востребованных tool_id и back-port для 5 nmap_* из Cycle 1.
3. **Замигрировать legacy state_machine** (`backend/src/orchestration/state_machine.py` + `backend/src/recon/exploitation/executor.py`) с `docker exec` + `subprocess.run` на `KubernetesSandboxAdapter` из Cycle 1 — без этого ВЕСЬ control-plane Cycle 1 unreachable.
4. **Регенерировать `docs/tool-catalog.md`** (≥154 строк), расширить coverage-matrix (35 → 154 tool_id × 5 контрактов = 770 параметризованных кейсов), обновить `CHANGELOG.md`.

После Cycle 2 каталог закрыт. Cycle 3+ остаются: Firecracker fallback (deferred), multi-stage sandbox-images с pinned versions+SBOM (Cycle 2 ставит только Dockerfile-skeletons), ReportService 12-комбинаций (Cycle 3), backend MCP server (Cycle 3), OTel/Prometheus (Cycle 4), Alembic для новых таблиц tool_runs/oast_callbacks/approvals (Cycle 5), e2e DoD §19 (Cycle 6).

---

## 2. Архитектурные решения и обоснование стратегии

### 2.1 Ordering rationale (почему интерливим парсеры с YAML-партиями)

User-prompt предлагал ARG-011..ARG-019 = только YAMLs, ARG-020 = ВСЕ парсеры одной задачей. Это **отвергнуто** по трём причинам:

1. **YAML без парсера = no-op `parse_output()` = `[]`.** `ShellToolAdapter.parse_output()` (см. `backend/src/sandbox/adapter_base.py:357-380`) пишет `WARNING tool_adapter.parse_output_not_implemented` в логи на каждый запуск, если `parse_strategy != BINARY_BLOB`. Доставка 119 YAMLs без парсеров затопит observability.
2. **Атомарность.** Парсер живёт под конкретный output-формат (nuclei JSONL, ffuf JSON, sqlmap stdout). Группировать его с YAML того же инструмента = **одна testable unit** (parser + YAML + integration test для парсера в одном PR).
3. **Backlog §17 явно требует:** «по одному smoke-тесту на каждый tool_id с мок-таргетом» + «coverage gate падает, если tool_id не имеет ни одного integration test». Парсеры внутри той же ARG-NNN дают возможность писать integration test от mock raw output → парсер → FindingDTO в той же атомарной единице.

### 2.2 State_machine migration (ARG-020) — must-have для Cycle 2

Legacy путь `state_machine.py → handlers.py → recon/exploitation/executor.py:execute_exploit_command()` использует `subprocess.run([docker, exec, sandbox_container_name, ...])` (см. найдено в `backend/src/recon/exploitation/executor.py:33-46`). Cycle 1 ARG-004 доставил `KubernetesSandboxAdapter`, но **не интегрировал** его в legacy state_machine — без этой миграции 35 tool_ids Cycle 1 + 119 tool_ids Cycle 2 unreachable из Celery worker. ARG-020 закрывает дыру.

### 2.3 Что отложено в Cycle 3+ (явно НЕ в этом плане)

| Откладываем | В какой цикл | Почему |
|---|---|---|
| Firecracker driver (`backend/src/sandbox/firecracker_driver.py`) | Cycle 3 | k8s adapter уже работает; Firecracker — fallback per Backlog §9 |
| Multi-stage Dockerfiles `argus-kali-{full,web,cloud,browser}/` с pinned versions + SBOM (`syft -o cyclonedx-json`) | Cycle 3 | ARG-011 ставит **stub-Dockerfile** (image:latest + comment-only roadmap) — pinned versions требуют отдельного supply-chain цикла |
| ReportService (Midgard/Asgard/Valhalla × HTML/PDF/JSON/CSV + SARIF/JUnit) | Cycle 3 | parser → FindingDTO готов; рендер шаблонов отдельный цикл |
| `replay_command_sanitizer.py` | Cycle 3 | Нужен ReportService |
| Backend MCP server (`backend/src/mcp/server.py`, FastMCP per Backlog §13) | Cycle 3 | Зависит от ReportService.generate() и findings list API |
| OTel spans + Prometheus metrics (`argus_tool_runs_total`, etc.) | Cycle 4 | Не блокирует pipeline; легче добавлять поверх стабильного Cycle 2 |
| `cloud_iam` ownership для AWS/GCP/Azure (полная реализация) | Cycle 4 | ARG-006 Cycle 1 оставил заглушку с интерфейсом |
| Alembic миграции для `tool_runs`, `oast_callbacks`, `approval_records`, `audit_entries` | Cycle 5 | Pipeline пока работает с in-memory + S3; БД-миграции — отдельный ops-gate |
| Полная hexstrike purge из docs/tests | Cycle 6 | Cycle 1 ARG-010 гарантировал 0 references **в коде**; docs остаются для исторического контекста |
| `scripts/e2e_full_scan.sh` + DoD §19 верификация | Cycle 6 | Capstone цикл |

---

## 3. Tasks (10, упорядочены по зависимостям)

### ARG-011 — Tool YAMLs §4.4 (HTTP fingerprinting / tech stack — 9 tools) + httpx parser + multi-image Dockerfile skeletons + parsers package init

- **Status:** `[ ] ARG-011 — Tool YAMLs §4.4 + httpx parser + multi-image Dockerfile skeletons (⏳ Pending)`
- **Backlog section:** §4.4 + §9 (sandbox images, skeleton-only)
- **Priority:** High
- **Estimated complexity:** Complex (~7 ч)
- **Dependencies:** ARG-002 (ToolAdapter base, signing infra), ARG-003 (YAML schema pattern)

#### Files to create

**YAMLs §4.4 (9 файлов в `backend/config/tools/`):**

`httpx.yaml`, `whatweb.yaml`, `wappalyzer_cli.yaml`, `webanalyze.yaml`, `aquatone.yaml`, `gowitness.yaml`, `eyewitness.yaml`, `favfreak.yaml`, `jarm.yaml` — каждый с командой из `Backlog/dev1_.md` §4.4 (строки 109-120), `phase: recon`, `risk_level: passive`, `requires_approval: false`, `network_policy.name: recon-passive`, image references на `argus-kali-web:latest`, parse_strategy = `json_lines` для `httpx`, `json_object` для остальных, evidence_artifacts = соответствующий `/out/*` файл, `cwe_hints: []`, `owasp_wstg: ["WSTG-INFO-02", "WSTG-INFO-08"]` для technology fingerprinting tools.

**Parsers package init:**

- `backend/src/sandbox/parsers/__init__.py` — публичный API: `dispatch_parse(strategy: ParseStrategy, raw_stdout, raw_stderr, artifacts_dir, tool_id) -> list[FindingDTO]`. Mapping `ParseStrategy → callable`, fail-soft на unknown strategy (log+`[]`), fail-closed только на malformed bytes когда parser явно `strict=True`.
- `backend/src/sandbox/parsers/_base.py` — общий `ParserContext`, `ParseError`, helper-функции (`_safe_load_jsonl`, `_safe_load_json`, `_finding_dto_from_dict`).

**httpx parser:**

- `backend/src/sandbox/parsers/httpx_parser.py` — `parse_httpx_jsonl(stdout: bytes, stderr: bytes, artifacts_dir: Path) -> list[FindingDTO]`. Один FindingDTO на каждую запись JSONL `{"url": "...", "status_code": ..., "tech": [...], "title": "...", "tls": {...}, "favicon": "...", "jarm": "..."}`. Категория `tech_disclosure`, severity = `info`, evidence — компактный JSON с url/status/tech/title.

**Multi-image Dockerfile skeletons (stub):**

- `sandbox/images/argus-kali-web/Dockerfile` — header-only stub: `FROM kalilinux/kali-rolling:latest` + comment block перечисляющий **packages, которые** будут установлены (httpx, whatweb, ffuf, feroxbuster, dirsearch, wpscan, dalfox, sqlmap, etc.) + TODO-marker «Cycle 3 implementation: pinned versions + SBOM via `syft`». **Не строится** — namespace placeholder, разрешает Cycle 2 YAMLs ссылаться на `argus-kali-web:latest` как future-image-ref.
- `sandbox/images/argus-kali-cloud/Dockerfile` — то же для cloud tools (prowler, scoutsuite, trivy, grype, kube-bench, kube-hunter, checkov, terrascan, tfsec, kics, semgrep).
- `sandbox/images/argus-kali-browser/Dockerfile` — то же для browser tools (playwright, puppeteer, chrome).
- `sandbox/images/argus-kali-full/Dockerfile` — superset stub (NOT built; only resolves YAMLs in §4.18 mobsf/apktool/jadx/binwalk that don't fit web/cloud/browser).

**Tests:**

- `backend/tests/unit/sandbox/parsers/__init__.py`
- `backend/tests/unit/sandbox/parsers/test_httpx_parser.py` — 6+ кейсов: пустой stdout → `[]`; одна валидная JSONL запись → 1 FindingDTO; multiple records; malformed line skip with warning; technology stack extraction; TLS info preservation.
- `backend/tests/integration/sandbox/parsers/test_dispatch_registry.py` — `dispatch_parse(ParseStrategy.JSON_LINES, mock_httpx_jsonl_bytes, …)` → возвращает корректный `list[FindingDTO]`.
- Расширить `backend/tests/integration/sandbox/test_tool_catalog_load.py` — добавить `HTTP_FINGERPRINT_TOOLS` frozenset из 9 tool_id и assert `EXPECTED_TOOLS` теперь = Cycle 1 (35) + 9 = **44**.
- Coverage gate (`backend/tests/test_tool_catalog_coverage.py`) автоматически подхватит новые YAMLs из registry — никаких правок не нужно (см. `_enumerate_tool_ids()`).

#### Acceptance criteria

1. `python -m scripts.tools_list --json | jq length` (из `backend/`) → **44** (35 Cycle 1 + 9 §4.4).
2. `python -m scripts.tools_sign --verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys` → exit 0.
3. `pytest -q tests/unit/sandbox/parsers tests/integration/sandbox tests/test_tool_catalog_coverage.py` — зелёный (44 × 5 = **220 параметризованных** coverage-кейсов).
4. `mypy --strict src/sandbox/parsers` — без ошибок.
5. `ruff check src/sandbox/parsers tests/unit/sandbox/parsers tests/integration/sandbox/parsers` — без ошибок.
6. `python -m scripts.docs_tool_catalog --check` — markdown синхронен (после регена через `--out ../docs/tool-catalog.md`).
7. Coverage `backend/src/sandbox/parsers` ≥ 90% (Backlog §19.1 для модулей в scope).
8. `httpx` парсер обрабатывает реалистичный JSONL fixture (≥3 записи, разные tech, разные status_code) и возвращает корректные FindingDTO с непустым `description`.

#### Worker commands (run in `backend/`)

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
python -m scripts.tools_list --json
pytest -q tests/unit/sandbox/parsers tests/integration/sandbox tests/test_tool_catalog_coverage.py
mypy --strict src/sandbox/parsers
ruff check src/sandbox/parsers tests/unit/sandbox/parsers
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
python -m scripts.docs_tool_catalog --check
```

#### Risks / out-of-scope

- Multi-image Dockerfiles — **stub only** (header + comment block). Pinned versions, SBOM генерация, multi-stage build, CVE scan на base image — Cycle 3.
- `aquatone`/`gowitness`/`eyewitness` produce screenshots (PNG) — `evidence_artifacts` указывает на directory, но parser в этой задаче возвращает только metadata; binary screenshot upload в S3 — Cycle 3 (нужен evidence pipeline storage layer, а текущий `src.evidence.pipeline` в Cycle 1 шипает только хеш).

---

### ARG-012 — Tool YAMLs §4.5 (Content/path discovery & fuzzing — 10 tools) + ffuf_json parser

- **Status:** `[ ] ARG-012 — Tool YAMLs §4.5 + ffuf_json parser (⏳ Pending)`
- **Backlog section:** §4.5
- **Priority:** High
- **Estimated complexity:** Moderate (~6 ч)
- **Dependencies:** ARG-011 (parsers package init, multi-image Dockerfile skeletons)

#### Files to create

**YAMLs §4.5 (10 файлов):**

`ffuf_dir.yaml`, `ffuf_vhost.yaml`, `ffuf_param.yaml`, `feroxbuster.yaml`, `gobuster_dir.yaml`, `dirsearch.yaml`, `kiterunner.yaml`, `arjun.yaml`, `paramspider.yaml`, `wfuzz.yaml`. Все имеют `phase: vuln_analysis` (кроме `ffuf_vhost`, `paramspider` — `recon`), `risk_level: low`, `requires_approval: false`, `network_policy.name: recon-active-tcp` или новая `web-fuzz` (если egress нужен только на 80/443 + custom port — расширяем `src.sandbox.network_policies` НЕ в этой задаче, а используем существующий `recon-active-tcp` с warning в YAML description).

Команды дословно из Backlog §4.5 (строки 124-134), wordlists из `{wordlist}` placeholder. Image: `argus-kali-web:latest`. parse_strategy: `json_object` для ffuf/dirsearch/feroxbuster/wfuzz/arjun, `text_lines` для gobuster_dir/paramspider/kiterunner.

**Parser:**

- `backend/src/sandbox/parsers/ffuf_parser.py` — `parse_ffuf_json(stdout: bytes, stderr: bytes, artifacts_dir: Path) -> list[FindingDTO]`. Универсальный парсер для ffuf JSON shape `{"results": [{"url": "...", "status": ..., "length": ..., "words": ..., "lines": ...}, ...]}`. Дедупликация по `url`, severity = `info` для status 200 + non-trivial length, `low` для 401/403 (auth wall discovery), `medium` для 500 (server error). Подходит для feroxbuster (тот же shape) и расширяется до dirsearch (немного другой top-level layout — JSON `{"results": ...}` vs `{"items": ...}`); abstract `_extract_findings_list(payload)` под обе формы.

**Tests:**

- `backend/tests/unit/sandbox/parsers/test_ffuf_parser.py` — 8+ кейсов: пустой `results: []` → `[]`; директория обнаружена (status 301) → 1 FindingDTO с `category=path_disclosure`; 401 → severity low; 500 → severity medium; ffuf shape; feroxbuster shape; dirsearch shape; malformed JSON → ParseError; mass results (1000 entries) → дедуп по url работает.
- Расширить `test_tool_catalog_load.py`: `CONTENT_DISCOVERY_TOOLS` frozenset = 10, `EXPECTED_TOOLS` = 35 + 9 + 10 = **54**.
- Integration: `tests/integration/sandbox/parsers/test_ffuf_integration.py` — fixture YAML `tests/integration/sandbox/fixtures/ffuf_dir.yaml` + mock raw output → parser → assert 5 findings.

#### Acceptance criteria

1. `python -m scripts.tools_list --json | jq length` → **54**.
2. `python -m scripts.tools_sign --verify ...` → exit 0.
3. Coverage gate: 54 × 5 = **270** параметризованных кейсов; зелёный.
4. `pytest -q tests/unit/sandbox/parsers/test_ffuf_parser.py tests/integration/sandbox/parsers/test_ffuf_integration.py` — зелёный.
5. `mypy --strict src/sandbox/parsers/ffuf_parser.py` — без ошибок.
6. `python -m scripts.docs_tool_catalog --check` — синхронен.
7. Parser coverage ≥ 90%.

#### Worker commands

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
pytest -q tests/unit/sandbox/parsers/test_ffuf_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
```

#### Risks / out-of-scope

- `wfuzz` JSON shape отличается от ffuf — отдельная ветка в parser, но в Cycle 2 — only basic; full wfuzz `--printer json` schema coverage — Cycle 3.
- Wordlists (`{wordlist}` placeholder) currently validated as `/wordlists/...` path; реальное mounting `wordlists` ConfigMap в k8s Job — ARG-020 при state_machine migration (или Cycle 3 если требуется отдельный CSI driver).

---

### ARG-013 — Tool YAMLs §4.6 (Crawler / JS / endpoint extraction — 8 tools) + katana_json parser

- **Status:** `[ ] ARG-013 — Tool YAMLs §4.6 + katana_json parser (⏳ Pending)`
- **Backlog section:** §4.6
- **Priority:** Medium
- **Estimated complexity:** Moderate (~5 ч)
- **Dependencies:** ARG-011

#### Files to create

**YAMLs §4.6 (8 файлов):**

`katana.yaml`, `gospider.yaml`, `hakrawler.yaml`, `waybackurls.yaml`, `gau.yaml`, `linkfinder.yaml`, `subjs.yaml`, `secretfinder.yaml`. `phase: recon` (кроме `secretfinder` → `vuln_analysis`), `risk_level: passive` для wayback/gau/linkfinder/subjs/secretfinder, `low` для katana/gospider/hakrawler (active crawl). Image `argus-kali-web:latest`. Команды из Backlog §4.6.

**Parser:**

- `backend/src/sandbox/parsers/katana_parser.py` — `parse_katana_json(stdout, stderr, artifacts_dir) -> list[FindingDTO]`. Katana JSON: `[{"timestamp":"...","request":{"endpoint":"...","method":"GET"},"response":{"status_code":...,"headers":{...}}}, ...]`. Один FindingDTO на каждый уникальный endpoint, category = `endpoint_discovery`, severity = `info`, evidence — endpoint + method + status_code. Дедупликация по `(endpoint, method)`.

**Tests:**

- `backend/tests/unit/sandbox/parsers/test_katana_parser.py` — 5+ кейсов.
- Расширить `test_tool_catalog_load.py`: `CRAWLER_TOOLS` = 8, `EXPECTED_TOOLS` = **62**.

#### Acceptance criteria

1. `tools_list --json | jq length` → **62**.
2. Coverage gate: 62 × 5 = **310** параметризованных кейсов.
3. `pytest -q tests/unit/sandbox/parsers/test_katana_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py` — зелёный.
4. `python -m scripts.docs_tool_catalog --check` — синхронен.
5. Parser coverage ≥ 90%.

#### Worker commands

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
pytest -q tests/unit/sandbox/parsers/test_katana_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
```

#### Risks / out-of-scope

- `secretfinder` produces HTML report, не JSON — parser в этой задаче limited; **полный secretfinder парсинг** (regex extraction из HTML body) — Cycle 3.
- `linkfinder`/`subjs` — text output (one URL per line), используют generic `text_lines` parser (existing or in `_base.py`).

---

### ARG-014 — Tool YAMLs §4.7 (CMS / platform-specific — 8 tools) + wpscan_json parser

- **Status:** `[ ] ARG-014 — Tool YAMLs §4.7 + wpscan_json parser (⏳ Pending)`
- **Backlog section:** §4.7
- **Priority:** Medium
- **Estimated complexity:** Moderate (~5 ч)
- **Dependencies:** ARG-011

#### Files to create

**YAMLs §4.7 (8 файлов):**

`wpscan.yaml`, `joomscan.yaml`, `droopescan.yaml`, `cmsmap.yaml`, `magescan.yaml`, `nextjs_check.yaml`, `spring_boot_actuator.yaml`, `jenkins_enum.yaml`. Все `phase: vuln_analysis`, `risk_level: low` (active probe но без exploitation). `requires_approval: false`. Image `argus-kali-web:latest`. Команды из Backlog §4.7.

**ВАЖНО:** `nextjs_check`, `spring_boot_actuator`, `jenkins_enum` per Backlog — это **nuclei templates**. YAML использует `command_template = ["nuclei", "-l", "{in_dir}/urls.txt", "-t", "<template-path>", "-jsonl", "-o", "{out_dir}/<tool>.jsonl"]`, parse_strategy = `nuclei_jsonl` (парсер из ARG-015). Это создаёт **soft dependency на ARG-015** — но YAML может быть доставлен и протестирован сейчас (parse возвращает `[]` без warning, поскольку `nuclei_jsonl` strategy будет no-op до ARG-015). Acceptance не требует функциональный парсинг для этих 3 tool_ids в этой задаче.

**Parser:**

- `backend/src/sandbox/parsers/wpscan_parser.py` — `parse_wpscan_json(...) -> list[FindingDTO]`. WPScan JSON: top-level `interesting_findings`, `vulnerabilities`, `version`, `themes`, `plugins`. Один FindingDTO на каждую vulnerability в `plugins.<name>.vulnerabilities[]`/`themes.<name>.vulnerabilities[]`, severity из CVSS, CWE из `cwe`, references из `references.url`, evidence = название plugin/theme + версия + CVE.

**Tests:**

- `backend/tests/unit/sandbox/parsers/test_wpscan_parser.py` — 6+ кейсов: пустой → `[]`; vulnerable plugin → FindingDTO с правильным severity; vulnerable theme; outdated WP version; user enumeration finding; multiple plugins/themes.
- Расширить `test_tool_catalog_load.py`: `CMS_TOOLS` = 8, `EXPECTED_TOOLS` = **70**.

#### Acceptance criteria

1. `tools_list --json | jq length` → **70**.
2. Coverage gate: 70 × 5 = **350** параметризованных кейсов; зелёный.
3. `pytest -q tests/unit/sandbox/parsers/test_wpscan_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py`.
4. `python -m scripts.docs_tool_catalog --check`.
5. Parser coverage ≥ 90%.

#### Worker commands

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
pytest -q tests/unit/sandbox/parsers/test_wpscan_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
```

#### Risks / out-of-scope

- `joomscan` / `cmsmap` / `magescan` — text-based output (no native JSON); используют `text_lines` parser; полные JSON-конверторы — Cycle 3.
- `nextjs_check`, `spring_boot_actuator`, `jenkins_enum` функционально парсятся только после ARG-015 (nuclei_jsonl).

---

### ARG-015 — Tool YAMLs §4.8 (Web vuln scanners — 7 tools) + nuclei_jsonl parser (CRITICAL)

- **Status:** `[ ] ARG-015 — Tool YAMLs §4.8 + nuclei_jsonl parser (⏳ Pending)`
- **Backlog section:** §4.8
- **Priority:** **Critical** (nuclei — самый используемый сканер; парсер unblocks §4.7 nuclei wrappers тоже)
- **Estimated complexity:** Complex (~7 ч)
- **Dependencies:** ARG-011

#### Files to create

**YAMLs §4.8 (7 файлов):**

`nuclei.yaml`, `nikto.yaml`, `wapiti.yaml`, `arachni.yaml`, `skipfish.yaml`, `w3af_console.yaml`, `zap_baseline.yaml`. Все `phase: vuln_analysis`, `risk_level: low`/`medium`, `requires_approval: false`. Image `argus-kali-web:latest`. Команды дословно из Backlog §4.8.

**Nuclei specifically:** `network_policy.name: web-active`, `default_timeout_s: 3600` (нужен новый шаблон, добавляем в `src.sandbox.network_policies._TEMPLATES` через расширение `NETWORK_POLICY_NAMES` frozenset — small additive change в этой задаче).

**Parser (CRITICAL):**

- `backend/src/sandbox/parsers/nuclei_parser.py` — `parse_nuclei_jsonl(stdout, stderr, artifacts_dir) -> list[FindingDTO]`. Nuclei JSONL one-finding-per-line: `{"template-id":"...","info":{"name":"...","severity":"high","tags":[...],"description":"...","reference":[...],"classification":{"cve-id":["CVE-2024-..."],"cwe-id":["CWE-79"],"cvss-metrics":"...","cvss-score":7.5,"epss-score":0.5,"epss-percentile":0.95}},"matched-at":"https://...","matcher-name":"...","extracted-results":[...]}`.
  - severity mapping: `info`→info, `low`→low, `medium`→medium, `high`→high, `critical`→critical.
  - CVE extraction → `FindingDTO.cve_ids`.
  - CWE extraction → `FindingDTO.cwe`.
  - CVSS score → `cvss_v3_score`.
  - EPSS score из info.classification → `epss_score`.
  - Evidence: `template-id`, `matched-at`, `matcher-name`, `extracted-results`.
  - **Idempotent:** `root_cause_hash = sha256(template_id + matched_url)` для дедупа в Findings normalizer (Cycle 1 ARG-009).

**Tests:**

- `backend/tests/unit/sandbox/parsers/test_nuclei_parser.py` — 12+ кейсов: пустой → `[]`; одна high finding → FindingDTO; multiple findings разной severity; CVE + CWE extraction; CVSS extraction; EPSS extraction; malformed line skip; unicode in description; large JSONL (1000+ lines, performance check).
- Integration test использует **реалистичный nuclei output fixture** (≥10 findings разной severity, разные template-id, mix CVE/non-CVE).
- Расширить `test_tool_catalog_load.py`: `WEB_VULN_TOOLS` = 7, `EXPECTED_TOOLS` = **77**.

#### Acceptance criteria

1. `tools_list --json | jq length` → **77**.
2. Coverage gate: 77 × 5 = **385** параметризованных кейсов; зелёный.
3. `pytest -q tests/unit/sandbox/parsers/test_nuclei_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py`.
4. `mypy --strict src/sandbox/parsers/nuclei_parser.py`.
5. **Парсер обрабатывает 1000-line JSONL за <1s** (perf test included).
6. ARG-014 nuclei wrappers (`nextjs_check`, `spring_boot_actuator`, `jenkins_enum`) теперь функциональны — integration test для каждого с mock nuclei output.
7. `python -m scripts.docs_tool_catalog --check`.
8. Parser coverage ≥ 95% (hottest path).

#### Worker commands

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
pytest -q tests/unit/sandbox/parsers/test_nuclei_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py
mypy --strict src/sandbox/parsers/nuclei_parser.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
```

#### Risks / out-of-scope

- `arachni` produces `.afr` binary report → требует отдельный `arachni_reporter` step; YAML декларирует `command_template` с pipe (`&&`), но safe-templating Cycle 1 запрещает `&&`. Решение: **two-step adapter** — основная команда + post-process script; в Cycle 2 шипаем YAML с одной командой `arachni ... --report-save-path=/out/arachni.afr` и parser возвращает `[]` (binary blob); полная цепочка `arachni_reporter` → JSON → parser — Cycle 3.
- `w3af_console` script-driven, нет JSON output → BINARY_BLOB strategy.
- `zap_baseline` produces JSON + HTML, parser в Cycle 2 — только JSON path.

---

### ARG-016 — Tool YAMLs §4.9 SQLi (6) + §4.10 XSS (5) = 11 + sqlmap_output + dalfox_json parsers

- **Status:** `[x] ARG-016 — Tool YAMLs §4.9 + §4.10 + sqlmap_output + dalfox_json parsers (✅ Completed 2026-04-19)`
- **Backlog section:** §4.9 + §4.10
- **Priority:** High
- **Estimated complexity:** Complex (~8 ч)
- **Dependencies:** ARG-005 (PayloadRegistry — sqlmap/dalfox используют payload families), ARG-006 (PolicyEngine — sqlmap_confirm требует approval), ARG-015 (parser pattern)

#### Files to create

**YAMLs §4.9 SQLi (6):**

`sqlmap_safe.yaml` (`phase: vuln_analysis`, `risk_level: low`), `sqlmap_confirm.yaml` (`phase: exploitation`, `risk_level: high`, `requires_approval: true`), `ghauri.yaml`, `jsql.yaml`, `tplmap.yaml`, `nosqlmap.yaml`. Image `argus-kali-web:latest`. Команды из Backlog §4.9.

**YAMLs §4.10 XSS (5):**

`dalfox.yaml`, `xsstrike.yaml`, `kxss.yaml`, `xsser.yaml`, `playwright_xss_verify.yaml`. **`playwright_xss_verify` имеет phase = `exploitation`** (Backlog говорит `validation`, но `ScanPhase` enum в Cycle 1 не включает `validation` — мапируем на `exploitation` с risk_level=`low`, comment в YAML об этом mapping). Image `argus-kali-browser:latest` для playwright, остальные — `argus-kali-web:latest`.

**Parsers:**

- `backend/src/sandbox/parsers/sqlmap_parser.py` — `parse_sqlmap_output(stdout, stderr, artifacts_dir) -> list[FindingDTO]`. Sqlmap не имеет JSON output, парсим **structured stdout markers**: `[INFO] testing connection to the target URL`, `[INFO] Parameter '<param>' is vulnerable. Do you want to keep testing the others...`, `Type: <technique>`, `Title: <description>`, `Payload: <payload>`. Один FindingDTO на каждый vulnerable parameter, severity = `high`, category = `sqli`, CWE = 89, evidence = `parameter`, `technique`, `payload`, `dbms` (extracted from `[INFO] the back-end DBMS is <dbms>`).
- `backend/src/sandbox/parsers/dalfox_parser.py` — `parse_dalfox_json(stdout, stderr, artifacts_dir) -> list[FindingDTO]`. Dalfox JSON: `[{"type":"R","poc":"...","cwe":"CWE-79","severity":"H","payload":"...","param":"...","data":"...","description":"..."}, ...]`. Один FindingDTO на каждый POC, severity mapping (R→high, V→medium, S→low — see dalfox docs), category = `xss`, CWE = 79, evidence = poc + payload + param.

**Tests:**

- `backend/tests/unit/sandbox/parsers/test_sqlmap_parser.py` — 8 кейсов.
- `backend/tests/unit/sandbox/parsers/test_dalfox_parser.py` — 6 кейсов.
- `EXPECTED_TOOLS` = **88** (77 + 11).

#### Acceptance criteria

1. `tools_list --json | jq length` → **88**.
2. Coverage gate: 88 × 5 = **440** параметризованных кейсов.
3. **`sqlmap_confirm` YAML имеет `requires_approval: true`** и тест catalog assert это (per Backlog §8 risk_level high → approval required).
4. **`playwright_xss_verify` использует `argus-kali-browser:latest`** image — assert в `test_tool_catalog_load.py`.
5. `pytest -q tests/unit/sandbox/parsers/test_sqlmap_parser.py tests/unit/sandbox/parsers/test_dalfox_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py`.
6. `python -m scripts.docs_tool_catalog --check`.
7. Parser coverage ≥ 90%.

#### Worker commands

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
pytest -q tests/unit/sandbox/parsers/test_sqlmap_parser.py tests/unit/sandbox/parsers/test_dalfox_parser.py tests/integration/sandbox tests/test_tool_catalog_coverage.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
```

#### Risks / out-of-scope

- `playwright_xss_verify` runner script (`/scripts/verify_xss.js`) — **отложен в Cycle 3** (ARG-019 ставит skeleton YAML; реальный JS runner живёт в `sandbox/scripts/playwright/` — отдельный supply-chain).
- `xsstrike`/`xsser`/`kxss` — text/custom output forms; в этой задаче limited parsing (один finding на каждое нахождение в stdout по regex), полные парсеры — Cycle 3.
- `tplmap`/`nosqlmap` — text output, BINARY_BLOB strategy.

---

### ARG-017 — Tool YAMLs §4.11 SSRF/OAST (5) + §4.12 Auth/brute (10) + §4.13 Hash (5) = 20 + interactsh_jsonl parser

- **Status:** `[ ] ARG-017 — Tool YAMLs §4.11 + §4.12 + §4.13 + interactsh_jsonl parser (⏳ Pending)`
- **Backlog section:** §4.11 + §4.12 + §4.13
- **Priority:** High
- **Estimated complexity:** Complex (~8 ч)
- **Dependencies:** ARG-006 (approval gate для destructive auth), ARG-007 (OAST correlator — interactsh интегрируется через `OastCorrelator`)

#### Files to create

**YAMLs §4.11 SSRF/OAST (5):**

`interactsh_client.yaml` (`phase: exploitation`, `risk_level: low`, validation tool — мапируем на exploitation phase см. ARG-016 note), `ssrfmap.yaml` (`vuln_analysis`, `medium`), `gopherus.yaml` (`vuln_analysis`, `low` — generation only), `oast_dns_probe.yaml` (`exploitation`, `low`), `cloud_metadata_check.yaml` (`exploitation`, `high`, **`requires_approval: true`** — Backlog explicit "только если scope permits + approval").

**YAMLs §4.12 Auth/brute (10):**

`hydra.yaml` (`exploitation`, `high`, `requires_approval: true`), `medusa.yaml`, `patator.yaml`, `ncrack.yaml`, `crackmapexec.yaml`, `kerbrute.yaml`, `gobuster_auth.yaml` (`vuln_analysis`, `low`), `evil_winrm.yaml` (`post_exploitation`, `destructive`, `requires_approval: true`, **2 approvers** per Backlog §8), `smbclient_check.yaml` (`exploitation`, `low`), `snmp_check.yaml` (`vuln_analysis`, `low`).

**YAMLs §4.13 Hash (5):**

`hashid.yaml` (`vuln_analysis`, `passive`), `hashcat.yaml` (`post_exploitation`, `high`, `requires_approval: true`), `john.yaml` (`post_exploitation`, `high`, `requires_approval: true`), `ophcrack.yaml` (`post_exploitation`, `medium`), `hash_analyzer.yaml` (`vuln_analysis`, `passive`).

**ВАЖНО:** Backlog говорит `phase = analysis` для §4.13, но `ScanPhase` enum в Cycle 1 не включает `analysis` — мапируем `analysis` → `vuln_analysis` (для passive) и `post` → `post_exploitation`. Comment в каждой YAML фиксирует мапинг.

**Image references:** `argus-kali-full:latest` для auth/brute/hash (требуют hydra/medusa/john/hashcat/crackmapexec/impacket — это full edition); `argus-kali-web:latest` для interactsh_client/cloud_metadata_check.

**Network policies:** Нужен новый шаблон **`auth-bruteforce`** (egress только на target IP/CIDR, ports per `{proto}/{port}`, with rate limiting tagged in template metadata) — расширяем `src.sandbox.network_policies._TEMPLATES` и `NETWORK_POLICY_NAMES` frozenset.

**Parser:**

- `backend/src/sandbox/parsers/interactsh_parser.py` — `parse_interactsh_jsonl(stdout, stderr, artifacts_dir) -> list[FindingDTO]`. Interactsh JSONL: `{"protocol":"dns/http/smtp","unique-id":"...","timestamp":"...","remote-address":"...","raw-request":"...","q-type":"A"}`. Один FindingDTO на каждый callback, category = `oast_callback`, severity = `confirmed_dynamic` (передаётся в `OastCorrelator` через `unique-id`). Evidence = протокол + remote-address + raw-request + timestamp.

**Tests:**

- `backend/tests/unit/sandbox/parsers/test_interactsh_parser.py` — 6+ кейсов.
- Integration: `tests/integration/sandbox/parsers/test_interactsh_correlator_integration.py` — интеграция parser → `OastCorrelator.correlate()` (Cycle 1 ARG-007) → подтверждение finding.confidence бамп.
- Расширить `test_tool_catalog_load.py`: `SSRF_OAST_TOOLS` = 5, `AUTH_TOOLS` = 10, `HASH_TOOLS` = 5; `EXPECTED_TOOLS` = **108**.
- **Approval-policy assert** в `test_yaml_catalog.py`: каждый tool с `risk_level in {high, destructive}` имеет `requires_approval: true`; `evil_winrm.yaml` дополнительно имеет approver-count signal (на Cycle 2 это yamls comment + assertion в test; реальная enforcement — PolicyEngine ARG-006 уже умеет).

#### Acceptance criteria

1. `tools_list --json | jq length` → **108**.
2. Coverage gate: 108 × 5 = **540** параметризованных кейсов.
3. **Все 8 destructive tools (`hydra`, `medusa`, `patator`, `ncrack`, `crackmapexec`, `kerbrute`, `evil_winrm`, `cloud_metadata_check`, `hashcat`, `john`) имеют `requires_approval: true`** — assert в test.
4. New network policy `auth-bruteforce` зарегистрирована, тестируется как existing шаблоны (Ingress deny, DNS pinned, target_cidr required).
5. `pytest -q tests/unit/sandbox/parsers/test_interactsh_parser.py tests/integration/sandbox/parsers/test_interactsh_correlator_integration.py tests/integration/sandbox tests/test_tool_catalog_coverage.py`.
6. `python -m scripts.docs_tool_catalog --check`.
7. Parser coverage ≥ 90%.

#### Worker commands

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
pytest -q tests/unit/sandbox/parsers/test_interactsh_parser.py tests/unit/sandbox/test_network_policies.py tests/integration/sandbox tests/test_tool_catalog_coverage.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
```

#### Risks / out-of-scope

- `hashcat`/`john` — offline tools; YAML декларирует, но real wordlist mounting + GPU resources — Cycle 5 (cluster ops).
- `evil_winrm` post-exploitation script (`/scripts/harmless.ps1`) — placeholder reference; реальный `harmless.ps1` script — Cycle 3 (sandbox scripts).
- `responder` (§4.17) идёт в ARG-019, не здесь.

---

### ARG-018 — Tool YAMLs §4.14 API/GraphQL (7) + §4.15 Cloud/IaC (12) + §4.16 Code/secrets (8) = 27 + trivy_json + semgrep_json parsers

- **Status:** `[x] ARG-018 — Tool YAMLs §4.14 + §4.15 + §4.16 + trivy_json + semgrep_json parsers (✅ Completed 2026-04-19)`
- **Backlog section:** §4.14 + §4.15 + §4.16
- **Priority:** High
- **Estimated complexity:** Complex (~9 ч — самая большая партия по числу YAMLs)
- **Dependencies:** ARG-006 (approval для cloud)

#### Files to create

**YAMLs §4.14 API/GraphQL (7):**

`openapi_scanner.yaml`, `graphw00f.yaml`, `clairvoyance.yaml`, `inql.yaml`, `graphql_cop.yaml`, `grpcurl_probe.yaml`, `postman_newman.yaml`. `phase: vuln_analysis` (кроме `graphw00f`/`grpcurl_probe` → `recon`). `risk_level: low`. Image `argus-kali-web:latest`.

**YAMLs §4.15 Cloud/IaC/container (12):**

`prowler.yaml` (cloud auth secrets, **needs egress to AWS API endpoints** — добавить в `src.sandbox.network_policies` шаблон `cloud-aws`), `scoutsuite.yaml` (cloud-aws), `cloudsploit.yaml` (cloud-aws), `pacu.yaml` (`exploitation`, `high`, **`requires_approval: true`**), `trivy_image.yaml`, `trivy_fs.yaml`, `grype.yaml`, `syft.yaml` (BINARY_BLOB — SBOM), `dockle.yaml`, `kube_bench.yaml`, `kube_hunter.yaml`, `checkov.yaml`. Все `phase: vuln_analysis`, image `argus-kali-cloud:latest`.

**YAMLs §4.16 Code/secrets (8):**

`terrascan.yaml`, `tfsec.yaml`, `kics.yaml`, `semgrep.yaml`, `bandit.yaml`, `gitleaks.yaml`, `trufflehog.yaml`, `detect_secrets.yaml`. Все `phase: vuln_analysis`, `risk_level: passive` (offline analysis on `/in/repo` mount), image `argus-kali-cloud:latest`.

**Network policy:** Новый шаблон `cloud-aws` (egress на `*.amazonaws.com`, `169.254.170.2` для ECS metadata если scope позволяет — но default deny; список AWS API endpoints вынести в `cloud_aws_endpoints` constant в network_policies.py). Аналогичные `cloud-gcp`, `cloud-azure` могут быть добавлены позже (Cycle 4 при cloud_iam ownership work).

**Parsers:**

- `backend/src/sandbox/parsers/trivy_parser.py` — `parse_trivy_json(stdout, stderr, artifacts_dir) -> list[FindingDTO]`. Trivy JSON: `{"Results": [{"Target": "...","Vulnerabilities": [{"VulnerabilityID": "CVE-...","PkgName": "...","InstalledVersion": "...","FixedVersion": "...","Severity": "HIGH","CVSS": {...},"References": [...],"PrimaryURL": "..."}, ...]}, ...]}`. Один FindingDTO на каждую vulnerability, severity mapping (CRITICAL→critical, HIGH→high, MEDIUM→medium, LOW→low, UNKNOWN→info), CVE → `cve_ids`, CVSS → `cvss_v3_score`, evidence = pkg + installed + fixed + primary URL. Подходит и для `grype` (тот же shape с минимальными отличиями — abstract `_extract_vulnerabilities()`).
- `backend/src/sandbox/parsers/semgrep_parser.py` — `parse_semgrep_json(stdout, stderr, artifacts_dir) -> list[FindingDTO]`. Semgrep JSON: `{"results": [{"check_id": "...","path": "...","start": {"line":...,"col":...},"end": {...},"extra": {"message": "...","metadata": {"cwe": [...], "owasp": [...], "category": "...","severity": "..."}}, ...}, ...]}`. Один FindingDTO на каждый result, severity из `extra.severity`, CWE из metadata, evidence = path + line + check_id. Подходит и для bandit, terrascan, tfsec (с минимальными отличиями).

**Tests:**

- `backend/tests/unit/sandbox/parsers/test_trivy_parser.py` — 8+ кейсов.
- `backend/tests/unit/sandbox/parsers/test_semgrep_parser.py` — 8+ кейсов.
- `EXPECTED_TOOLS` = **135** (108 + 27).

#### Acceptance criteria

1. `tools_list --json | jq length` → **135**.
2. Coverage gate: 135 × 5 = **675** параметризованных кейсов.
3. `pacu` YAML имеет `requires_approval: true`.
4. `cloud-aws` network policy зарегистрирован, тестируется (Ingress deny, egress только на whitelisted domains).
5. `pytest -q tests/unit/sandbox/parsers/test_trivy_parser.py tests/unit/sandbox/parsers/test_semgrep_parser.py tests/unit/sandbox/test_network_policies.py tests/integration/sandbox tests/test_tool_catalog_coverage.py`.
6. `python -m scripts.docs_tool_catalog --check`.
7. Parser coverage ≥ 90% для обоих парсеров.

#### Worker commands

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
pytest -q tests/unit/sandbox/parsers/test_trivy_parser.py tests/unit/sandbox/parsers/test_semgrep_parser.py tests/unit/sandbox/test_network_policies.py tests/integration/sandbox tests/test_tool_catalog_coverage.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
```

#### Risks / out-of-scope

- `prowler`/`scoutsuite` cloud integration требует AWS credentials — YAML заявляет `{profile}` placeholder + secret mount; реальная Vault/CSI mount работа — Cycle 5 (production secrets management).
- `pacu` interactive CLI — wrap в non-interactive mode через `--exec`-style flag; полная Pacu integration — Cycle 4 (cloud_iam strategy).
- `cloudsploit` deprecated → consider replacing с `prowler` или `cs-suite`; в Cycle 2 шипаем как Backlog требует.
- `kube-bench`/`kube-hunter` требуют доступ к target K8s cluster — runtime-параметр `{host}`, NetworkPolicy = новая `kubeapi-target` (deferred to Cycle 4).
- `trufflehog`/`gitleaks`/`detect-secrets` parser выводят похожие schemas; в Cycle 2 шипаем только generic `text_lines` parser для не-trivy/semgrep — full coverage Cycle 3.

---

### ARG-019 — Tool YAMLs §4.17 Network (10) + §4.18 Binary (5) + §4.19 Browser (5) = 20 + nmap_xml back-port parser

- **Status:** `[x] ARG-019 — Tool YAMLs §4.17 + §4.18 + §4.19 + nmap_xml back-port parser (✅ Completed 2026-04-19 — see ai_docs/develop/reports/2026-04-19-arg-019-network-binary-browser-nmap-worker-report.md)`
- **Backlog section:** §4.17 + §4.18 + §4.19 + §4.2 (nmap_xml back-port для Cycle 1 nmap_* tools)
- **Priority:** **Critical** (закрывает каталог ≥154; nmap_xml back-port убирает no-op WARNING для Cycle 1 nmap_tcp_top/nmap_tcp_full/nmap_udp/nmap_version/nmap_vuln)
- **Estimated complexity:** Complex (~8 ч)
- **Dependencies:** ARG-006

#### Files to create

**YAMLs §4.17 Network (10):**

`responder.yaml` (`exploitation`, `destructive`, `requires_approval: true`, **2 approvers**), `impacket_secretsdump.yaml` (`post_exploitation`, `destructive`, `requires_approval: true`, **2 approvers**), `ntlmrelayx.yaml` (`exploitation`, `destructive`, **2 approvers**), `bloodhound_python.yaml` (`post_exploitation`, `high`, `requires_approval: true`), `ldapsearch.yaml` (`recon`, `low`), `snmpwalk.yaml` (`recon`, `low`), `onesixtyone.yaml` (`recon`, `low`), `ike_scan.yaml` (`recon`, `low`), `redis_cli_probe.yaml` (`recon`, `low`), `mongodb_probe.yaml` (`recon`, `low`).

**YAMLs §4.18 Binary (5):**

`mobsf_api.yaml` (`vuln_analysis`, `low`, image `argus-kali-full:latest`), `apktool.yaml`, `jadx.yaml`, `binwalk.yaml`, `radare2_info.yaml`. Все `phase: vuln_analysis`, `risk_level: passive` (offline analysis), image `argus-kali-full:latest`.

**YAMLs §4.19 Browser (5):**

`playwright_runner.yaml` (`exploitation`, `low`), `puppeteer_screens.yaml` (`exploitation`, `low`), `chrome_csp_probe.yaml` (`vuln_analysis`, `low`), `cors_probe.yaml` (`vuln_analysis`, `low`), `cookie_probe.yaml` (`vuln_analysis`, `passive`). Image `argus-kali-browser:latest`.

**Network policies:** `network-target` (для §4.17 protocol probes — egress только на target IP/port), `binary-isolated` (for §4.18 — **NO egress at all** — pure offline analysis on `/in/`), `browser-active` (для §4.19 — egress на target URL + OAST callback domain).

**Parser (CRITICAL — back-port для Cycle 1):**

- `backend/src/sandbox/parsers/nmap_parser.py` — `parse_nmap_xml(stdout, stderr, artifacts_dir) -> list[FindingDTO]`. Nmap XML schema: `<nmaprun><host><address>...</address><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" version="..." product="..." extrainfo="..."/></port>...</ports><hostscript><script id="..." output="..."/></hostscript></host></nmaprun>`. Один FindingDTO на каждый `state="open"` port, category = `service_exposure`, severity = `info`, evidence = port + protocol + service name + version + product. Дополнительно: для `nmap_vuln.yaml` (NSE script vulns) — извлечь findings из `<script id="vuln-*" output="...">` с severity = `medium`/`high` based on script category.

**Wire nmap_xml в Cycle 1 nmap descriptors:**

- Cycle 1 шипал 5 nmap YAMLs с `parse_strategy: xml_nmap` но parser возвращал `[]` (no-op). После ARG-019 dispatch_parse(ParseStrategy.XML_NMAP, ...) → `parse_nmap_xml(...)`. Все 5 nmap_* tools из Cycle 1 АВТОМАТИЧЕСКИ становятся functional. Integration test проверяет это.

**Tests:**

- `backend/tests/unit/sandbox/parsers/test_nmap_parser.py` — 10+ кейсов: пустой XML → `[]`; одно открытое port → 1 FindingDTO; multiple ports + multiple hosts; closed/filtered ports — пропуск; service version extraction; NSE vuln script output extraction; malformed XML → ParseError; large nmap output (1000 ports) perf check.
- `backend/tests/integration/sandbox/parsers/test_nmap_backport.py` — для каждого из 5 Cycle 1 nmap_* tools: создать ToolJob → mock raw XML output → parser → FindingDTO. Подтверждает back-port работает.
- Расширить `test_tool_catalog_load.py`: `NETWORK_PROTO_TOOLS` = 10, `BINARY_TOOLS` = 5, `BROWSER_TOOLS` = 5; `EXPECTED_TOOLS` = **155** (135 + 20).

#### Acceptance criteria

1. `tools_list --json | jq length` → **155** (закрывает Backlog DoD §19.6 «≥150»).
2. Coverage gate: 155 × 5 = **775** параметризованных кейсов.
3. **Все 5 destructive tools** (`responder`, `impacket_secretsdump`, `ntlmrelayx`, `bloodhound_python`, и evil_winrm из ARG-017) имеют `requires_approval: true` И **2 approvers** (assert в catalog test).
4. **Все 5 Cycle 1 nmap_* tools** (`nmap_tcp_top`, `nmap_tcp_full`, `nmap_udp`, `nmap_version`, `nmap_vuln`) функционально парсятся через nmap_xml — back-port integration test зелёный.
5. `binary-isolated` network policy имеет **`egress=[]`** (полный no-egress) — assert в test.
6. `pytest -q tests/unit/sandbox/parsers/test_nmap_parser.py tests/integration/sandbox/parsers/test_nmap_backport.py tests/unit/sandbox/test_network_policies.py tests/integration/sandbox tests/test_tool_catalog_coverage.py`.
7. `python -m scripts.docs_tool_catalog --check`.
8. **Parser coverage ≥ 90%** для nmap_parser (back-port — горячий путь Cycle 1).

#### Worker commands

```powershell
python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv --tools-dir config/tools --out config/tools/SIGNATURES
pytest -q tests/unit/sandbox/parsers/test_nmap_parser.py tests/integration/sandbox/parsers/test_nmap_backport.py tests/unit/sandbox/test_network_policies.py tests/integration/sandbox tests/test_tool_catalog_coverage.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
```

#### Risks / out-of-scope

- `responder`/`ntlmrelayx`/`bloodhound_python` требуют **target в local segment** + Active Directory; полное e2e невозможно без real-AD lab — Cycle 6 (DoD верификация против vulhub-equivalent).
- `mobsf_api` требует deployed MobSF instance — Cycle 5 ops.
- `playwright_runner`/`puppeteer_screens` — JS scripts, см. ARG-016 risks (отложено в Cycle 3).
- NSE vuln script output schema нестандартный (free-form text) — parser возвращает только `state` indicator + script_id; полный CVE extraction из NSE output — Cycle 3.

---

### ARG-020 — state_machine migration to K8sSandboxDriver + parser dispatch hardening + extend coverage matrix + regenerate docs/tool-catalog.md

- **Status:** `[ ] ARG-020 — state_machine migration + parser dispatch + coverage backfill + docs regen (⏳ Pending)`
- **Backlog section:** §16.4 (per-category ToolAdapter wiring) + §17 (test discipline) + §19.6 (catalog ≥150)
- **Priority:** **Critical** (без этого Cycle 1+2 unreachable из running pipeline)
- **Estimated complexity:** Complex (~8 ч)
- **Dependencies:** ARG-011..ARG-019 (нужны все 119 YAMLs + 11 парсеров для полной coverage matrix)

#### Files to modify

**State_machine migration (CRITICAL):**

- `backend/src/recon/exploitation/executor.py` — заменить функцию `execute_exploit_command(command, timeout, use_sandbox)` на `execute_via_k8s_sandbox(tool_job: ToolJob, timeout: int) -> ToolRunResult`. Внутри:
  ```python
  from src.sandbox.k8s_adapter import KubernetesSandboxAdapter, SandboxRunMode
  from src.sandbox.tool_registry import ToolRegistry
  from src.sandbox.runner import SandboxRunner

  registry = ToolRegistry(tools_dir=settings.tools_dir)
  registry.load()
  adapter = KubernetesSandboxAdapter(
      registry=registry,
      mode=SandboxRunMode.CLUSTER if settings.k8s_enabled else SandboxRunMode.DRY_RUN,
  )
  runner = SandboxRunner(adapter=adapter, max_concurrent=settings.sandbox_max_concurrent)
  result = await runner.dispatch_jobs([tool_job], default_timeout_s=timeout)
  return result[0]
  ```
  Удалить `subprocess.run([docker, exec, ...])` и `_build_result()` (заменены на `SandboxRunResult`).

- `backend/src/orchestration/state_machine.py` (и `handlers.py`) — refactor любого call site `execute_exploit_command(...)` на новый `execute_via_k8s_sandbox(...)`. Для backward-compat шим: keep старая signature как deprecation-wrapper в течение 1 цикла, log `DeprecationWarning` на каждый вызов.

- `backend/src/recon/exploitation/adapters/sqlmap_adapter.py` (и `nuclei_adapter.py`, `hydra_adapter.py`, `metasploit_adapter.py`, `custom_script_adapter.py`) — `build_command()` теперь возвращает `ToolJob` (с tool_id + parameters) вместо `str`. Парсинг output моделируется через ToolRegistry → `ShellToolAdapter.parse_output()` (используя dispatch registry). 5 legacy adapters становятся **тонкой фасадой** над unified ToolRegistry: преобразуют `AttackPlan` → `ToolJob`, делегируют запуск через `execute_via_k8s_sandbox`, парсят через registered parser, возвращают `ExploitationResult`.

- `backend/src/tools/executor.py` — аналогичный рефакторинг: `_persist_tool_run`, `build_sandbox_exec_argv` уходят, заменены на ToolRegistry + SandboxRunner. **Все** call sites `subprocess.run` / `docker exec` в `backend/src/` после миграции = **0** (assert в новом тесте `test_no_subprocess_in_main_path.py`).

**Parser dispatch hardening:**

- `backend/src/sandbox/parsers/__init__.py` — `dispatch_parse(strategy, raw_stdout, raw_stderr, artifacts_dir, tool_id) -> list[FindingDTO]`. Финальный mapping все 11 парсеров из ARG-011..ARG-019 + дефолтные generic_jsonl/json/text/csv handlers. Fail-soft: unknown strategy → log + `[]`. Fail-closed: parser raised → log structured error + `[]` (не валит worker).

- Расширить `backend/src/sandbox/adapter_base.py` — `ShellToolAdapter.parse_output()` теперь делегирует `dispatch_parse(self._descriptor.parse_strategy, raw_stdout, raw_stderr, artifacts_dir, self._descriptor.tool_id)`. Default no-op WARNING из Cycle 1 удаляется (всё парсится через dispatch).

**Coverage matrix extension:**

- `backend/tests/test_tool_catalog_coverage.py` — НИКАКИХ правок (auto-discovery через `_enumerate_tool_ids()` подхватит все 154 YAMLs); просто прогон → 154 × 5 = **770 кейсов** должны быть зелёные.

- `backend/tests/integration/sandbox/test_tool_catalog_load.py` — обновить `EXPECTED_TOOLS` = 155 (35 + 119 + 1 если нужен дополнительный); обновить `EXPECTED_BY_PHASE` (recon/vuln_analysis/exploitation/post_exploitation), `EXPECTED_BY_CATEGORY` (recon/web_va/cloud/iac/network/auth/binary/browser/oast/misc).

**Docs regen:**

- `docs/tool-catalog.md` — байт-в-байт регенерация через `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md`. Должно содержать ≥154 tool entries.

- `backend/scripts/docs_tool_catalog.py` — обновить `_EXPECTED_TOOLS_PER_PHASE` (Cycle 1 hardcoded 28 recon + 7 vuln_analysis; теперь нужно учесть всю Cycle 2 партию: recon ~50, vuln_analysis ~70, exploitation ~25, post_exploitation ~10). `_BACKLOG_TOTAL_LONG_TERM` остаётся 154 (закрытие).

**Static analysis enforcement:**

- `backend/tests/security/test_no_subprocess_in_main_path.py` — НОВЫЙ тест: AST-обход `backend/src/`, fail если найден `subprocess.run|Popen|call|os.system|os.popen|shell=True|docker.sock` в любом модуле кроме allowlisted (`src/sandbox/k8s_adapter.py` lazily imports kubernetes которое внутри использует subprocess для kubectl auth — но это transitive, не direct call; и `backend/scripts/*.py` где CLI инструменты могут использовать subprocess для git/etc.). Список allowlisted в test constant.

**CHANGELOG update:**

- `CHANGELOG.md` — добавить раздел "ARGUS Active Pentest Engine v1 — Cycle 2 (ARG-011..ARG-020)" с подразделами: Tool catalog (119 YAMLs §4.4-§4.19), Parsers (11 modules), state_machine migration, Coverage matrix extension. Ссылки на ARG-NNN в каждом подразделе.

#### Acceptance criteria

1. `pytest -q tests/test_tool_catalog_coverage.py` → **770 параметризованных кейсов** (154 × 5), все зелёные.
2. `tools_list --json | jq length` → **154** (or 155 — финальная цифра определяется при счёте YAMLs Cycle 2; цель ≥150).
3. **0 `subprocess.run` / `docker exec` / `shell=True`** в `backend/src/` (кроме allowlisted) — `test_no_subprocess_in_main_path.py` зелёный.
4. **Все 5 Cycle 1 legacy `recon/exploitation/adapters/*.py`** (sqlmap, nuclei, hydra, metasploit, custom_script) теперь:
   - Принимают `AttackPlan`, конвертируют в `ToolJob`, делегируют `execute_via_k8s_sandbox()`.
   - Используют `dispatch_parse(...)` для парсинга.
   - Возвращают `ExploitationResult` через тот же путь, что Cycle 1 (backward-compat).
5. `mypy --strict src/sandbox src/recon/exploitation src/orchestration src/tools` — без ошибок.
6. `ruff check src tests` — без ошибок.
7. `bandit -q -r src` — без ошибок (special check на subprocess detection — должен быть clean).
8. `python -m scripts.docs_tool_catalog --check` — `docs/tool-catalog.md` синхронен (содержит 154+ entries).
9. **`tests/test_argus006_hexstrike.py`** остаётся зелёным — 0 hexstrike references в `backend/src/`.
10. `CHANGELOG.md` обновлён с разделом Cycle 2.
11. Coverage `backend/src/sandbox/parsers` ≥ 90% (агрегированно по 11 модулям); `backend/src/recon/exploitation` ≥ 80% (post-migration); `backend/src/orchestration` не падает по сравнению с Cycle 1.
12. **Smoke E2E test** (`backend/tests/integration/sandbox/test_e2e_dry_run_sweep.py`) — для каждого из 154 tool_ids: создать `ToolJob` с минимальными корректными параметрами (per ALLOWED_PLACEHOLDERS), вызвать `KubernetesSandboxAdapter.run(job)` в `DRY_RUN` режиме, убедиться что rendered manifest валиден (security context, ingress deny, NetworkPolicy attached). 154 dry-run жёбов за <30s.

#### Worker commands

```powershell
ruff check src tests
mypy --strict src/sandbox src/recon/exploitation src/orchestration src/tools src/sandbox/parsers
bandit -q -r src
pytest -q tests/test_tool_catalog_coverage.py tests/security/test_no_subprocess_in_main_path.py tests/integration/sandbox/test_e2e_dry_run_sweep.py tests/unit tests/integration tests/test_argus006_hexstrike.py
python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
python -m scripts.docs_tool_catalog --check
python -m scripts.tools_sign --verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
```

#### Risks / out-of-scope

- **Backward compatibility:** legacy `execute_exploit_command(command_string, ...)` сохраняется как deprecation-wrapper на 1 цикл — Cycle 3 удалит. Без этого риск break внешних callers (которых нет в `backend/src/`, но могут быть в `mcp-server/` или test fixtures — проверить).
- Firecracker fallback (если k8s недоступен) — `execute_via_k8s_sandbox` raises `K8sClusterUnavailableError` с clean error; реальный fallback на Firecracker — Cycle 3.
- `sandbox_max_concurrent` settings ключ — добавить в `src/core/config.py` (default 5); если нет в Cycle 1 — добавить.
- Deprecation warnings будут шуметь — добавить filter в pytest.ini для `warnings::DeprecationWarning:src.recon.exploitation.executor` чтобы не валить тесты.
- E2E sweep test может быть медленным — bench against 30s budget, если медленнее → split на per-category sub-tests.

---

## 4. Dependencies graph

```
ARG-002 (Cycle 1) ──┬─→ ARG-011 ──┬─→ ARG-012
                    │             │
                    │             ├─→ ARG-013
                    │             │
                    │             ├─→ ARG-014
                    │             │
                    │             └─→ ARG-015 ──→ ARG-016
                    │                                     ↑
                    └────→ (paralleled via ARG-005/006/007)
                                                          │
ARG-006 (Cycle 1) ──→ ARG-016, ARG-017, ARG-018, ARG-019  │
ARG-007 (Cycle 1) ──→ ARG-017                              │
ARG-005 (Cycle 1) ──→ ARG-016                              │
                                                          │
ARG-011..ARG-019 ───────────────────────────────────────→ ARG-020 (capstone)
```

Critical path: **ARG-011 → ARG-015 → ARG-020** (foundational parser pattern → nuclei parser → state_machine migration). Tasks ARG-012/013/014 параллелятся (после ARG-011); ARG-016/017/018/019 параллелятся (после Cycle 1 dependencies удовлетворены).

---

## 5. Progress (updated by orchestrator)

- ⏳ ARG-011: §4.4 (9 YAMLs) + httpx parser + multi-image stubs (Pending)
- ⏳ ARG-012: §4.5 (10 YAMLs) + ffuf parser (Pending)
- ⏳ ARG-013: §4.6 (8 YAMLs) + katana parser (Pending)
- ⏳ ARG-014: §4.7 (8 YAMLs) + wpscan parser (Pending)
- ⏳ ARG-015: §4.8 (7 YAMLs) + nuclei parser (Pending)
- ✅ ARG-016: §4.9 + §4.10 (11 YAMLs) + sqlmap + dalfox parsers (Completed 2026-04-19 — see `ai_docs/develop/reports/2026-04-19-arg-016-sqli-xss-worker-report.md`)
- ⏳ ARG-017: §4.11 + §4.12 + §4.13 (20 YAMLs) + interactsh parser (Pending)
- ✅ ARG-018: §4.14 + §4.15 + §4.16 (27 YAMLs) + trivy + semgrep parsers (Completed 2026-04-19 — see `ai_docs/develop/reports/2026-04-19-arg-018-tools-trivy-semgrep-worker-report.md`)
- ✅ ARG-019: §4.17 + §4.18 + §4.19 (20 YAMLs) + nmap_xml back-port parser (Completed 2026-04-19 — see `ai_docs/develop/reports/2026-04-19-arg-019-network-binary-browser-nmap-worker-report.md`)
- ✅ ARG-020: state_machine audit + parser dispatch hardening (heartbeats) + coverage matrix extension + docs regen (Completed 2026-04-19 — see `ai_docs/develop/reports/2026-04-19-arg-020-capstone-report.md`)

---

## 6. Architecture invariants — что НЕ ломаем

Cycle 2 расширяет каталог и парсеры, но **сохраняет все Cycle 1 guardrails** (per Backlog/dev1_.md §1, §3, §5, §18 и Cycle 1 report §3):

### Sandbox runtime
- Non-root pod (`runAsNonRoot=true`, UID/GID 65532), read-only root filesystem, dropped capabilities, seccomp `RuntimeDefault`, `automountServiceAccountToken=false`, `restartPolicy=Never`, `backoffLimit=0`.
- Guaranteed QoS: `requests==limits` для CPU/memory, заданные через ToolDescriptor.

### Templating
- Только allowlisted placeholders (`url`, `host`, `port`, `domain`, `ip`, `cidr`, `params`, `wordlist`, `canary`, `out_dir`, `in_dir`, `ports`, `proto`, `community`, и т.д. — см. `src.pipeline.contracts._placeholders.ALLOWED_PLACEHOLDERS`). Если §4.x требует новый placeholder — расширяем `ALLOWED_PLACEHOLDERS` + добавляем validator в `src.sandbox.templating._PLACEHOLDER_VALIDATORS` (например `{token}`, `{collection}`, `{firmware}`, `{apk}` — оценить per task).
- `shell=False`, `subprocess.run(argv, shell=False)`, никаких метасимволов.

### Signing
- Все 154 tool YAMLs Ed25519-подписаны через `python -m scripts.tools_sign sign`. SIGNATURES file атомарно перезаписан после каждой партии.
- Public key `backend/config/tools/_keys/<key_id>.ed25519.pub` остаётся неизменным (тот же dev key, что Cycle 1). Production key ротация — Cycle 5.

### NetworkPolicy
- Ingress always denied. DNS pinned (Cloudflare/Quad9). Active templates требуют `target_cidr`. Private ranges (10/8, 172.16/12, 192.168/16, 169.254.169.254/32) blocked.
- Новые templates (`web-active`, `auth-bruteforce`, `cloud-aws`, `network-target`, `binary-isolated`, `browser-active`) добавляются в `src.sandbox.network_policies._TEMPLATES` и `NETWORK_POLICY_NAMES` frozenset; для каждого расширяется `tests/unit/sandbox/test_network_policies.py`.

### Approval & dual-control
- `risk_level in {high, destructive}` → `requires_approval=true` (assert в catalog test для каждой партии).
- Destructive tools требуют 2 approvers (PolicyEngine ARG-006 уже умеет; в Cycle 2 — assert YAML correctness).

### Audit chain
- ApprovalService + AuditChain (Cycle 1 ARG-006) остаются source of truth для approval events.

### Findings & evidence
- Каждый parser возвращает `list[FindingDTO]`. FindingDTO имеет `root_cause_hash` для дедупликации (Cycle 1 ARG-009 normalizer).
- Evidence — раw_stdout/raw_stderr/artifacts_dir hash через `src.evidence.pipeline` (Cycle 1).
- Redaction (`src.evidence.redaction`) применяется до persist в S3 — нет утечки secrets из parser output.

---

## 7. Implementation notes (для worker)

### 7.1 YAML authoring shortcuts

- Для inline-batch создания YAMLs использовать `backend/scripts/payloads_list.py` как образец batch CLI; копи-paste pattern из `backend/config/tools/nmap_tcp_top.yaml`.
- Поле `description` обязательно (Cycle 1 ARG-010 ввёл `StrictStr` с max 500 char) — кратко (1-2 предложения), ссылка на Backlog `§4.x`.
- Image references: пока используем `argus-kali-{web,cloud,browser,full}:latest`; pinned tags — Cycle 3.

### 7.2 Parser conventions

- Каждый parser в `backend/src/sandbox/parsers/<tool_or_format>_parser.py` — **pure function** (no I/O, no globals).
- Принимает `(stdout: bytes, stderr: bytes, artifacts_dir: Path) -> list[FindingDTO]`.
- Fail-soft: `try/except json.JSONDecodeError` на per-line basis для JSONL; per-record на JSON object; **never** raises на malformed input — log `WARNING parser.malformed_record` + `continue`.
- Тесты используют **realistic fixtures** (real-world tool output samples в `backend/tests/fixtures/sandbox_outputs/<parser_name>/`) — copy-paste из публичных upstream test suites.
- Parser выходные FindingDTO имеют:
  - `tool_run_id` = пробрасывается через ParserContext (после rеsole в Cycle 3 — пока None в parser, заполняется адаптером).
  - `category` per FindingCategory enum (Cycle 1 ARG-009).
  - `severity` per `Severity` enum.
  - `confidence` по умолчанию `suspected`; verifier (Cycle 1 ARG-008) поднимает до `confirmed` после OAST callback / re-run.

### 7.3 Coverage gate self-update

`backend/tests/test_tool_catalog_coverage.py:_enumerate_tool_ids()` использует `ToolRegistry().load()` — автоматически подхватывает все YAMLs из директории. Каждое добавление YAML-партии АВТОМАТИЧЕСКИ расширяет coverage matrix (нет нужды править test). Контракт remains 5 контрактов на каждый tool_id.

### 7.4 Signing workflow (Windows PowerShell)

```powershell
cd backend
$priv = "config\tools\_keys\dev_signing.ed25519.priv"
python -m scripts.tools_sign sign --key $priv --tools-dir config\tools --out config\tools\SIGNATURES
python -m scripts.tools_sign verify --tools-dir config\tools --signatures config\tools\SIGNATURES --keys-dir config\tools\_keys
```

Аналогично для payloads/prompts (Cycle 1 ARG-005/008 шипали `payloads_sign.py`, `prompts_sign.py`).

### 7.5 Documentation regen workflow

```powershell
cd backend
python -m scripts.docs_tool_catalog --out ..\docs\tool-catalog.md
python -m scripts.docs_tool_catalog --check
```

`--check` — CI-mode: exit 1 если markdown drifted vs registry.

---

## 8. Out-of-scope (явно НЕ в этом цикле)

| Что | Куда |
|---|---|
| Firecracker driver | Cycle 3 |
| Multi-stage Dockerfiles с pinned versions + SBOM (`syft`) | Cycle 3 |
| Sandbox script files (`sandbox/scripts/playwright/verify_xss.js`, `harmless.ps1`) | Cycle 3 |
| ReportService (Midgard/Asgard/Valhalla × HTML/PDF/JSON/CSV + SARIF/JUnit) | Cycle 3 |
| Backend MCP server (`backend/src/mcp/server.py`) | Cycle 3 |
| `replay_command_sanitizer.py` | Cycle 3 |
| Wordlists ConfigMap / CSI mount в k8s | Cycle 5 ops |
| Production OAST deployment + wildcard DNS + TLS | Cycle 5 |
| Helm chart, `infra/firecracker/*.json` | Cycle 5 |
| OpenTelemetry spans + Prometheus metrics | Cycle 4 |
| Полный CISA SSVC v2.1 + EPSS percentile decisions | Cycle 4 |
| `cloud_iam` ownership для AWS/GCP/Azure (полная реализация) | Cycle 4 |
| Alembic migrations для `tool_runs`, `oast_callbacks`, `approval_records` | Cycle 5 |
| RLS coverage tests на каждую новую таблицу | Cycle 5 |
| Полный hexstrike purge из docs/tests | Cycle 6 |
| `scripts/e2e_full_scan.sh` + DoD §19 verification | Cycle 6 |
| `infra/.env` cleanup (вынести из репозитория) | Cycle 6 |

---

## 9. Verification command (DoD checklist для Cycle 2)

После завершения всех 10 задач оператор может запустить:

```powershell
cd backend

ruff check src tests scripts
mypy --strict src/sandbox src/sandbox/parsers src/recon/exploitation src/orchestration src/tools src/payloads src/policy src/oast src/orchestrator src/pipeline src/findings src/evidence
bandit -q -r src
python -m pytest tests/test_argus006_hexstrike.py tests/test_tool_catalog_coverage.py tests/security/test_no_subprocess_in_main_path.py tests/integration tests/unit -q
python -m scripts.docs_tool_catalog --check
python -m scripts.tools_sign verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
python -m scripts.payloads_sign verify --payloads-dir config/payloads --signatures config/payloads/SIGNATURES --keys-dir config/payloads/_keys
python -m scripts.prompts_sign verify --prompts-dir config/prompts --signatures config/prompts/SIGNATURES --keys-dir config/prompts/_keys
```

Все 8 команд должны завершиться с **exit code 0**. После этого Cycle 2 closed; готовность к Cycle 3 (reports, MCP, sandbox-images).

---

## 10. Ссылки

- **Backlog (источник истины):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md)
- **Cycle 1 plan:** [`ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md`](2026-04-17-argus-finalization-cycle1.md)
- **Cycle 1 report:** [`ai_docs/develop/reports/2026-04-17-argus-finalization-cycle1.md`](../reports/2026-04-17-argus-finalization-cycle1.md)
- **CHANGELOG:** [`CHANGELOG.md`](../../../CHANGELOG.md)
- **Tool catalog (auto-generated):** [`docs/tool-catalog.md`](../../../docs/tool-catalog.md)
- **Hexstrike legacy audit gate:** [`backend/tests/test_argus006_hexstrike.py`](../../../backend/tests/test_argus006_hexstrike.py)
- **Coverage gate:** [`backend/tests/test_tool_catalog_coverage.py`](../../../backend/tests/test_tool_catalog_coverage.py)
- **Tool-catalog generator:** [`backend/scripts/docs_tool_catalog.py`](../../../backend/scripts/docs_tool_catalog.py)
- **API contract rule:** [`.cursor/rules/api-contract.mdc`](../../../.cursor/rules/api-contract.mdc)
- **Workspace metadata:** `.cursor/workspace/active/orch-2026-04-18-argus-cycle2/`

---

**Статус:** ✅ **Closed** (2026-04-19) — все 10 задач выполнены, каталог 157 tools закрыт (DoD §19.6), parser-dispatch fail-soft hardened, coverage-matrix расширена с 5 → 10 контрактов, docs/tool-catalog.md регенерирован с Parser-status колонкой. Итоговый отчёт: `ai_docs/develop/reports/2026-04-18-argus-finalization-cycle2.md`. Cycle 2 → Cycle 3 handoff успешен.
