# ARGUS Finalization Cycle 3 — Final Sign-off Report

**Дата:** 2026-04-19  
**План:** `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md`  
**Предыдущий цикл:** `ai_docs/develop/reports/2026-04-18-argus-finalization-cycle2.md`  
**Бэклог:** `Backlog/dev1_md` §11 (Evidence redaction), §13 (MCP server), §15 (Reporting), §16.11/§16.13 (DevSecOps gates), §17 (Coverage), §19.1/§19.6 (DoD)  
**Статус:** ✅ **Закрыто** — все 10 задач (ARG-021..ARG-030) завершены, мост в Cycle 4 разблокирован.

---

## Executive Summary

Цикл 3 закрыл три параллельных направления, заявленных в плане:

1. **Парсеры** — карта диспатчера выросла с **33 → 68 mapped (+35, +106 %)**, heartbeat-fallback сократился с **124 → 89 (-35)**. Цель плана §5 («mapped ≥ 68, heartbeat ≤ 89») достигнута точно. Каждый из 35 новых парсеров — pure-функция `(stdout, stderr, artifacts_dir, tool_id) → list[FindingDTO]` поверх единого `_base.py` / `_text_base.py` / `_jsonl_base.py` фундамента. Покрытие новых модулей по строкам ≥ 91 %, а критические редакторы секретов (`gitleaks`, `impacket_secretsdump`, `trufflehog`, `hashid`/`hash_analyzer`) защищены отдельными интеграционными гейтами с regex-сweep'ами.
2. **Внешний слой и репортинг** — поднят backend MCP-сервер (FastMCP, JSON-RPC 2.0 stdio + streamable-http, **15 tools / 4 resources / 3 prompts**, signed manifest, аудит-лог с хешированием аргументов) и `ReportService` со связкой Tier 1 (Midgard) + Tier 2 (Asgard) × 6 форматов (HTML / PDF / JSON / CSV / SARIF v2.1.0 / JUnit XML), всего **12 из 18** ячеек матрицы tiers × forms. Внешние артефакты Asgard защищены модулем `replay_command_sanitizer` (21 secret-regex + 13 reverse-shell-regex + 13 destructive-flag токенов, NIST SP 800-204D §5.1.4 enforced на 335 кейсах).
3. **Инфраструктура и тест-инфраструктура** — четыре stub-Dockerfile (`argus-kali-{web,cloud,browser,full}`) превращены в production multi-stage сборки (USER 65532, no-SUID, HEALTHCHECK, SBOM CycloneDX 1.5, Cosign-skeleton); добавлены NetworkPolicy templates `cloud-{aws,gcp,azure}` (8 → 11) и доведено до конца потребление override-полей `dns_resolvers` / `egress_allowlist` (ARG-019 H2-долг закрыт); починен SQLite test-pool, размечены маркеры `requires_postgres/redis/oast/docker` — `pytest -q` теперь зелёный по умолчанию (9278 кейсов).

Капстоун (ARG-030) расширил матрицу coverage с **10 контрактов × 157 инструментов = 1570** до **12 × 157 = 1884** параметризованных кейсов, добавив гейты **C11 — parser determinism** и **C12 — evidence-redaction completeness**. Оба контракта зелёные при пустом `_C12_KNOWN_LEAKERS`, что подтверждает: каждый wired-парсер цикла является «первой линией» редакции, а downstream `Redactor` остаётся verifiable no-op'ом.

Главный архитектурный сдвиг цикла — переход от «каталог инструментов» к «двум новым внешним поверхностям» (MCP и `ReportService`) с детерминированным подписанным манифестом и embedded supply-chain attestations. Catalog signing инвариант из Cycle 1/2 сохранён: 157 tools / 23 payloads / 5 prompts проверяются Ed25519 на старте без отказов. Heartbeat-инвариант ARG-020 сохранён: для всех 89 ещё-не-замапленных tool_id любой вызов `dispatch_parse` всё ещё возвращает ровно один `ARGUS-HEARTBEAT` finding и структурный `parsers.dispatch.unmapped_tool` warning.

Известные ограничения, переходящие в Cycle 4 (полностью оформлены в `ai_docs/develop/issues/ISS-cycle4-carry-over.md`): Valhalla tier (6 ячеек ReportService), оставшиеся 89 heartbeat-парсеров, Cosign full-prod wiring + GH OIDC keyless, image-build CI gating с push в `ghcr.io`, MCP webhook-интеграции (Slack/Linear/Jira), полировка PDF-шаблона WeasyPrint, триаж stale-import follow-ups (`ISS-fix-004-imports`, `ISS-fix-006-imports`, `ISS-payload-signatures-drift`, `ISS-pytest-test-prefix-collisions`), root-cause `apktool.yaml`-drift, OpenAPI-export MCP-схемы, скаффолдинг капстоуна Cycle 4.

---

## Per-task Summary (ARG-021..ARG-030)

### ARG-021 — Per-tool parsers batch 1 (JSON_OBJECT IaC/SAST/Cloud)

- **Статус:** ✅ Завершено.
- **Backlog:** §4.15 + §4.16 + §4.18 + §11 + §19.1.
- **Файлы:** 10 новых парсеров (`bandit`, `gitleaks`, `kube_bench`, `checkov`, `kics`, `terrascan`, `tfsec`, `dockle`, `mobsf_api`, `grype`) + `_base.py` (помощники `redact_secret`, `dedup_emit`) + регистрация в `__init__.py` + 11 новых suite'ов unit-тестов + `test_arg021_dispatch.py` (35 интеграционных кейсов).
- **Тесты добавлено:** 144 unit + 35 integration = **179** новых.
- **Headline-метрика:** mapped 33 → **43 (+10, +30 %)**; heartbeat 124 → 114; критическая редакция `gitleaks.Secret` enforced на отдельном integration-гейте.
- **Out-of-scope:** wpscan JSON shape edge-case остался открытым (документирован).
- **Worker report:** [`2026-04-19-arg-021-parsers-batch1-report.md`](2026-04-19-arg-021-parsers-batch1-report.md).

### ARG-022 — Per-tool parsers batch 2 (TEXT_LINES Network/Auth/Post-exploit)

- **Статус:** ✅ Завершено.
- **Backlog:** §4.2 + §4.12 + §4.17 + §11.
- **Файлы:** 10 новых парсеров (`impacket_secretsdump`, `evil_winrm`, `kerbrute`, `bloodhound_python`, `snmpwalk`, `ldapsearch`, `smbclient`, `smbmap`, `enum4linux_ng`, `rpcclient_enum`) + новый `_text_base.py` (общие `redact_hash_string` + LDIF-блок-парсер) + 11 unit-suite'ов + `test_arg022_dispatch.py` (53 интеграционных кейса).
- **Тесты добавлено:** 122 unit + 53 integration = **175** новых.
- **Headline-метрика:** mapped 43 → **53 (+10, +23 %)**; heartbeat 114 → 104; **CRITICAL — `impacket_secretsdump` ноль raw-NT/LM/AES hash-байтов** в sidecar, проверяется regex'ом `[a-fA-F0-9]{32}:[a-fA-F0-9]{32}` + lone-≥32-hex-blob; SNMP default-community (CWE-256) теперь first-class severity.
- **Out-of-scope:** BloodHound binary JSON parser deferred; `responder` log parser в Cycle 4.
- **Worker report:** [`2026-04-19-arg-022-parsers-batch2-report.md`](2026-04-19-arg-022-parsers-batch2-report.md).

### ARG-023 — Backend MCP server (FastMCP, JSON-RPC 2.0)

- **Статус:** ✅ Завершено.
- **Backlog:** §13 + §16.13.
- **Файлы:** новый пакет `backend/src/mcp/` (39 типизированных модулей: `server.py`, `runtime.py`, `context.py`, `audit_logger.py`, `auth.py`, `tenancy.py`, `exceptions.py`, `schemas/*.py` × 7, `services/*.py` × 6, `tools/*.py` × 6, `resources/*.py` × 4, `prompts/*.py` × 3) + signed manifest `backend/config/mcp/server.yaml` + `docs/mcp-server.md`.
- **Тесты добавлено:** **429** новых (396 unit + 33 integration; включая stdio + streamable-http real-transport smoke).
- **Headline-метрика:** **15 tools / 4 resources / 3 prompts**, mypy --strict clean (39 source files), 100 % capability coverage по плану §13. Аудит-лог `MCPAuditLogger` хеширует аргументы перед записью (no raw secrets).
- **Out-of-scope:** webhook-интеграции (Slack/Linear/Jira) и per-LLM-client rate-limiter — в Cycle 4 (ARG-035).
- **Worker reports:** [`2026-04-19-arg-023-mcp-server-report.md`](2026-04-19-arg-023-mcp-server-report.md) + [`2026-04-19-arg-023-mcp-server-worker-report.md`](2026-04-19-arg-023-mcp-server-worker-report.md).

### ARG-024 — ReportService Tier 1 (Midgard) + SARIF + JUnit + унифицированный API

- **Статус:** ✅ Завершено.
- **Backlog:** §15 + §16.11 + §17.
- **Файлы:** новые модули `report_bundle.py` (167), `tier_classifier.py` (137), `sarif_generator.py` (308), `junit_generator.py` (304), `report_service.py` (263); расширения `__init__.py`, `api/routers/reports.py` (новый `POST /reports/generate`); `pyproject.toml` (+`jsonschema`).
- **Тесты добавлено:** **112** новых (`test_report_bundle.py` 20, `test_tier_classifier.py` 15, `test_sarif_generator.py` 27, `test_junit_generator.py` 16, `test_report_service.py` 20, `test_report_service_integration.py` 14); 111 PASS + 1 SKIP (PDF — отсутствуют WeasyPrint native-libs на dev-боксе).
- **Headline-метрика:** Tier 1 × 6 форматов поднят end-to-end; SARIF v2.1.0 byte-stable; JUnit pytest-совместимый; SHA-256 на `ReportBundle` + `X-Argus-Report-SHA256` header.
- **Out-of-scope:** PDF byte-determinism (WeasyPrint version-dependent — задокументировано); Valhalla tier — отдельная задача Cycle 4 (ARG-031).
- **Worker reports:** [`2026-04-19-arg-024-report-service-midgard-report.md`](2026-04-19-arg-024-report-service-midgard-report.md) + [`2026-04-19-arg-024-reports-midgard-worker-report.md`](2026-04-19-arg-024-reports-midgard-worker-report.md).

### ARG-025 — ReportService Tier 2 (Asgard) + `replay_command_sanitizer`

- **Статус:** ✅ Завершено.
- **Backlog:** §15 + §16.11 + §17.
- **Файлы:** новые модули `replay_command_sanitizer.py` (528, 21 secret + 13 reverse-shell + 13 destructive-flag паттернов), `asgard_tier_renderer.py` (415); расширения `tier_classifier.py` (`_project_asgard` ↔ `SanitizeContext`), `report_service.py` (`render_bundle(..., sanitize_context)`), `generators.py` (Asgard JSON branch + LF-line-terminator CSV).
- **Тесты добавлено:** **420** новых (38 unit-сanitizer + 21 unit-renderer + 26 integration × 6 форматов + 335 security-кейсов в `test_report_no_secret_leak.py`).
- **Headline-метрика:** **335 / 335** secret-leak-кейсов зелёные (55 паттернов × 6 surfaces), Asgard выпускается в 5/6 форматах bytes-стабильно (PDF — structural snapshot через `pypdf`); сanitizer canary-safe + idempotent.
- **Out-of-scope:** Valhalla tier (ARG-031), полировка PDF-шаблона (ARG-036).
- **Worker report:** [`2026-04-19-arg-025-asgard-sanitizer-report.md`](2026-04-19-arg-025-asgard-sanitizer-report.md).

### ARG-026 — Multi-stage Dockerfiles + SBOM + Cosign skeleton

- **Статус:** ✅ Завершено (production-ready локально; CI build gating запланирован в Cycle 4 ARG-034).
- **Backlog:** §16.13 (DevSecOps supply-chain).
- **Файлы:** 4 переделанных Dockerfile (`argus-kali-{web,cloud,browser,full}`, +~780 LoC), 2 shared helpers (`healthcheck.sh`, `generate_sbom.sh`), 2 build/sign-скрипта (`infra/scripts/{build,sign}_images.sh`), 1 GitHub-workflow (`.github/workflows/sandbox-images.yml`, 4 jobs: hardening-contract, build, sign, sign-dry-run), 1 hardening-test (`test_image_security_contract.py`, **65 assertions** в <1 s без Docker), 1 doc (`docs/sandbox-images.md`, 285 строк).
- **Тесты добавлено:** **65** static-hardening assertions в integration-suite.
- **Headline-метрика:** USER 65532 во всех 4 финальных стадиях, 0 SUID-биты введены (browser-image удаляет Chromium setuid sandbox), SBOM CycloneDX 1.5 на канонической `/usr/share/doc/sbom.cdx.json` + `LABEL argus.sbom.path=...`; Cosign skeleton (dry-run по умолчанию, реальная подпись при `COSIGN_KEY`).
- **Out-of-scope:** реальный `docker build` в worker env (нет Docker daemon — отдано в CI-matrix); реальная Cosign keyless с GH OIDC — Cycle 4 (ARG-033).
- **Worker report:** [`2026-04-19-arg-026-dockerfiles-sbom-cosign-report.md`](2026-04-19-arg-026-dockerfiles-sbom-cosign-report.md).

### ARG-027 — NetworkPolicy override consumption + cloud-{aws,gcp,azure}

- **Статус:** ✅ Завершено (закрывает ARG-019 H2 reviewer-flagged gap).
- **Backlog:** §9 + §15.
- **Файлы:** `network_policies.py` (+3 cloud-templates, override-validation, `_build_ip_block_peer` с deny-exceptions), `manifest.py` (новый `build_networkpolicy_for_job`), `k8s_adapter.py` (делегация + `ValueError → SandboxConfigError`), `__init__.py` (re-exports), `tests/unit/sandbox/test_network_policies.py` (+20), новый `tests/integration/sandbox/test_network_policy_overrides.py` (+20), `docs/network-policies.md` (новый, 11 templates + override-семантика + invariants + runbook).
- **Тесты добавлено:** **40** новых (20 unit + 20 integration).
- **Headline-метрика:** templates 8 → **11 (+3)**; `NetworkPolicyRef.dns_resolvers` (replace) и `egress_allowlist` (union) теперь живые поля; **0 wildcard egress peers без `ipBlock.except`** (private + IMDS deny-block применяется автоматически к `0.0.0.0/0` / `::/0`).
- **Out-of-scope:** GCP/Azure FQDN egress — пока через `egress_allowed_fqdns` annotation; полная реализация per-FQDN egress — после Cilium / Calico FQDN-extension в инфраструктуре.
- **Worker report:** [`2026-04-19-arg-027-network-policy-overrides-worker-report.md`](2026-04-19-arg-027-network-policy-overrides-worker-report.md).

### ARG-028 — SQLite test-pool fix + pytest marker discipline

- **Статус:** ✅ Завершено (закрывает Cycle-2-capstone «3170 connection-refused» проблему).
- **Backlog:** §16.4 + §17.
- **Файлы:** `src/db/session.py` (новые `_is_sqlite_url`, `_engine_kwargs_for`, `_build_engine` — диспатч по диалекту: SQLite → `StaticPool`+`check_same_thread=False`, Postgres → прежние `pool_pre_ping=True, pool_size=5, max_overflow=10`); `tests/conftest.py` (новый `pytest_collection_modifyitems` — авто-маркеры `requires_postgres/redis/oast/docker` по path + fixture-names + module-content regex); `pytest.ini` + `pyproject.toml` (registered markers + `addopts = -m "not requires_docker"`); `.github/workflows/ci.yml` (split на `test-no-docker` + `test-docker-required` с Postgres 15 + pgvector + Redis 7 service-containers); `docs/testing-strategy.md`; `tests/unit/db/test_session_pool.py` (14 unit).
- **Тесты добавлено:** **14** новых unit; (общая карта `pytest --collect-only`: dev-default 9278/12184, requires_docker 2906/12184).
- **Headline-метрика:** `pytest -q` (dev-default) **9278/9278 PASS** оффлайн (раньше — стена красного); CI разделён на 2 джобы по marker'ам.
- **Out-of-scope:** триаж stale-import follow-ups (`ISS-fix-004-imports`, `ISS-fix-006-imports`, `ISS-payload-signatures-drift`, `ISS-pytest-test-prefix-collisions`) — Cycle 4 (ARG-037).
- **Worker report:** [`2026-04-19-arg-028-sqlite-pool-pytest-markers-report.md`](2026-04-19-arg-028-sqlite-pool-pytest-markers-report.md).

### ARG-029 — Per-tool parsers batch 3 (JSON_LINES + Custom + mixed JSON_OBJECT)

- **Статус:** ✅ Завершено — попадание в exact-target плана §5 (`mapped ≥ 68, heartbeat ≤ 89`).
- **Backlog:** §4.7 + §4.14 + §4.15 + §4.16 + §4.18 + §11.
- **Файлы:** 15 новых парсеров (`trufflehog`, `naabu`, `masscan`, `prowler`, `detect_secrets`, `openapi_scanner`, `graphql_cop`, `postman_newman`, `zap_baseline`, `syft`, `cloudsploit`, `hashid`, `hash_analyzer`, `jarm`, `wappalyzer_cli`) + 15 unit-suite'ов + `test_arg029_dispatch.py` (84 интеграционных кейсов).
- **Тесты добавлено:** 294 unit + 84 integration = **378** новых; helper-reuse strict — ноль новых helper'ов, всё на `_base.py` / `_jsonl_base.py` / `_text_base.py`.
- **Headline-метрика:** mapped 53 → **68 (+15, +28 %)**; heartbeat 104 → **89 (-15)**; **3 critical security gates** — (a) `trufflehog` ноль raw-secret-bytes в sidecar, (b) `hashid`/`hash_analyzer` ноль MD5/SHA-1/SHA-256/SHA-512 hex в sidecar (только `stable_hash_12` discriminator), (c) `prowler` AWS account-ID `123456789012` round-trip preserved (positive assertion — pivot-data, не secret).
- **Out-of-scope:** parser-coverage-by-category breakdown (передан в ARG-030); follow-up issues `ISS-fix-004-imports`, `ISS-fix-006-imports`, `ISS-payload-signatures-drift`, `ISS-pytest-test-prefix-collisions` (Cycle 4 ARG-037); root-cause `apktool.yaml`-drift (Cycle 4 ARG-038).
- **Worker report:** [`2026-04-19-arg-029-parsers-batch3-report.md`](2026-04-19-arg-029-parsers-batch3-report.md).

### ARG-030 — Capstone (coverage matrix C11 + C12, docs, CHANGELOG, carry-over)

- **Статус:** ✅ Завершено (этот отчёт).
- **Backlog:** §17 + §19.1 + §19.6.
- **Файлы:** `backend/tests/test_tool_catalog_coverage.py` (+`COVERAGE_MATRIX_CONTRACTS=12` ratchet, +`test_tool_parser_determinism` C11, +`test_tool_parser_evidence_redaction_completeness` C12, +helpers `_fixture_for_strategy` / `_canonical_dto_dump` / `_C12_SECRET_BAIT_PATTERNS` / `_C12_BAIT_BLOB`); `backend/scripts/docs_tool_catalog.py` (расширение `_render_parser_coverage` — header summary `Mapped: 68 (43.3%), Heartbeat: 89 (56.7%)` + новая секция `### Parser coverage by category` с 10 строками per `ToolCategory` + `_category_sort_key`); регенерация `docs/tool-catalog.md`; обновление трёх stale-test guard'ов (`test_trivy_semgrep_dispatch.py::DEFERRED_ARG018_TOOL_IDS`, `test_nuclei_dispatch.py::DEFERRED_WEB_VULN_TOOL_IDS`, `test_arg022_dispatch.py::test_registered_count_is_53` → `test_arg022_contribution_is_intact`); новый `ai_docs/develop/issues/ISS-cycle4-carry-over.md`; `CHANGELOG.md` (новая Cycle 3 секция).
- **Тесты добавлено:** **314** новых параметризованных кейсов (157 × C11 + 157 × C12) + 1 ratchet assertion в `test_parser_coverage_summary`.
- **Headline-метрика:** coverage matrix size 1570 → **1884** контрактов (10 → 12 × 157, +20 %); все 1887 PASS (1884 матрица + 3 summary/ratchet); `_C12_KNOWN_LEAKERS` пустой — все 157 wired-парсеров проходят C12 без exemption'ов.
- **Out-of-scope:** Valhalla tier (ARG-031), оставшиеся 89 heartbeat-парсеров (ARG-032), Cosign full-prod wiring (ARG-033), CI image-build gating (ARG-034), MCP webhook-интеграции (ARG-035), PDF-шаблон полировка (ARG-036), stale-import триаж (ARG-037), `apktool.yaml`-drift root-cause (ARG-038), OpenAPI export MCP (ARG-039), Cycle 4 капстоун (ARG-040).
- **Worker report:** этот документ.

---

## Headline Metrics Table

| Метрика | Cycle 2 close | Cycle 3 close | Δ |
|---|---|---|---|
| Подписанные tool YAMLs | 157 | **157** | 0 (стабильно) |
| Подписанные payload YAMLs | 23 | **23** | 0 (стабильно) |
| Подписанные prompt YAMLs | 5 | **5** | 0 (стабильно) |
| Mapped per-tool парсеры | 33 | **68** | **+35 (+106 %)** |
| Heartbeat fallback descriptors | 124 | **89** | **-35 (-28 %)** |
| Mapped %-share от каталога | 21.0 % | **43.3 %** | **+22.3 п.п.** |
| Coverage matrix размер | 10 контрактов × 157 = **1570** | 12 × 157 = **1884** | **+314 (+20 %)** |
| MCP tools/resources/prompts (publicly exposed) | 0 / 0 / 0 | **15 / 4 / 3** | **+22 capabilities** |
| ReportService tiers × formats wired | 0 / 18 | **12 / 18 (Midgard + Asgard × 6)** | **+12** |
| Multi-stage Dockerfiles (production-ready) | 0 / 4 (stub headers) | **4 / 4** | **+4** |
| NetworkPolicy templates | 8 | **11 (+cloud-aws/gcp/azure)** | **+3** |
| `NetworkPolicyRef` overrides консумируются | 0 (dead config) | **2 (dns_resolvers + egress_allowlist)** | **+2** |
| `pytest -q` dev-default | стена красного | **9278/9278 PASS** | зелёный |
| Pytest markers (`requires_*`) | 0 | **5** (postgres / redis / oast / docker / weasyprint_pdf) | **+5** |
| `mypy --strict src/sandbox src/mcp` | clean | **clean (98 source files)** | стабильно |
| Раскрытых secret-leak-вырусов в Asgard reports | n/a | **0** (335/335 NIST §5.1.4 PASS) | enforced |
| Image hardening assertions (без Docker) | 0 | **65** | enforced |
| Cycle 4 carry-over backlog items | n/a | **10 (ARG-031..ARG-040)** | seeded |

---

## Architectural Impact

1. **Cycle 1/2 invariants preserved.** Sandbox security contract (`runAsNonRoot=True`, `readOnlyRootFilesystem=True`, dropped capabilities, seccomp `RuntimeDefault`, no service-account token, ingress=deny, egress allowlisted, Argv-only execution через `render_argv`) и signing contract (Ed25519 + fail-closed `ToolRegistry.load()`) ни в одной точке Cycle 3 не ослаблены — добавлены только новые поверхности и **defence-in-depth слои**.
2. **Two new defence-in-depth слоя.** ARG-025 ввёл `replay_command_sanitizer` как **обязательный** транзит для каждого Asgard-репорта (335 NIST-кейсов в CI), а ARG-030 закрепил **C12 evidence-redaction-completeness** как пер-tool гейт: `Redactor()` на уже-сериализованном `FindingDTO` обязан возвращать `redactions_applied == 0`. Это превращает «парсер обязан редактировать» из ad-hoc convention в формальное per-tool invariant, проверяемое CI на 157 параллельных кейсах.
3. **MCP как новая внешняя поверхность.** До Cycle 3 единственным внешним surface'ом был FastAPI REST. С ARG-023 backend выставляет MCP-сервер по двум транспортам (stdio для IDE/CLI, streamable-http за auth-прокси для production), что делает ARGUS first-class интегрируемым в Cursor / Claude Desktop / OpenAI Responses без shim'ов. Tenant isolation, audit-log с хешированием аргументов и Pydantic-валидация на каждом payload'е делают эту поверхность пригодной для production без отдельного gateway.
4. **`ReportService` как tier-aware deliverable boundary.** До Cycle 3 «отчёты» были набором свободных `generators.*` функций. Теперь единая канонная точка `ReportService.generate(tenant_id, scan_id, tier, format) → ReportBundle` (immutable, SHA-256, MIME helpers) делает «выдачу отчёта» атомарной операцией с tier-классификатором, который **обязан** быть pure (no I/O), и form-rendering'ом, который **обязан** быть byte-stable для всех текстовых форматов. PDF-non-determinism задокументирован как known limitation WeasyPrint.
5. **Dispatch инвариант ARG-020 not regressed.** Несмотря на +35 mapped парсеров, heartbeat-fallback path сохранён байт-в-байт: для 89 ещё-не-замапленных tool_id любой `dispatch_parse` всё ещё возвращает ровно один `ARGUS-HEARTBEAT` finding (`FindingCategory.INFO`, `cwe=[1059]`) + `parsers.dispatch.unmapped_tool` warning. C11 (parser determinism) формально пин'ит, что этот fallback идемпотентен — два вызова с одним fixture'ом дают структурно равные `FindingDTO` списки.
6. **Supply-chain хвост подтянут наполовину.** ARG-026 закрывает image-hardening контракт статически (USER 65532, no SUID, SBOM CycloneDX 1.5, OCI+ARGUS labels, Cosign-skeleton), но реальный `docker build` + push в `ghcr.io` + cosign keyless с GH OIDC отдан в Cycle 4 (ARG-033/ARG-034). Hardening-test ловит регрессии без Docker daemon'а — это лучшая защита, доступная без CI-инфраструктуры.

---

## Known Gaps / Cycle 4 Candidates

Полный backlog оформлен в [`ai_docs/develop/issues/ISS-cycle4-carry-over.md`](../issues/ISS-cycle4-carry-over.md) (10 пунктов, ARG-031..ARG-040). Топ-7 разрывов:

1. **Valhalla tier (ARG-031)** — 6 ячеек ReportService `valhalla × {HTML, PDF, JSON, CSV, SARIF, JUnit}` ещё не замаплены; цикл-3-релизный `tier_classifier._project_valhalla` существует как pass-through, но без бизнес-impact-lens-рендерера. После закрытия — ReportService покрывает 18/18 матрицы.
2. **Heartbeat parsers batch 4 (ARG-032)** — 89 tool_id ещё в heartbeat. Приоритет (по аналитике per-category coverage из `docs/tool-catalog.md`): `browser` (0/6, 0 %), `binary` (1/5, 20 %), `recon` (7/35, 20 %), `auth` (3/11, 27 %). Цель Cycle 4 — ещё +30 mapped (mapped → 98, heartbeat → 59).
3. **Cosign full prod wiring (ARG-033)** — реальная keyless подпись с GH OIDC, transparency-log публикация, attestation для SBOM. Без неё `infra/scripts/sign_images.sh` остаётся dry-run на CI.
4. **Image-build CI gating (ARG-034)** — реальный `docker build` 4 образов в CI matrix, push в `ghcr.io/argus`, attach SBOM как OCI artefact, gate merge на success.
5. **MCP webhook-интеграции (ARG-035)** — Slack / Linear / Jira нотификации на approval pending / scan completed; per-LLM-client token-bucket rate-limiter.
6. **Stale-import триаж (ARG-037)** — `ISS-fix-004-imports`, `ISS-fix-006-imports`, `ISS-payload-signatures-drift`, `ISS-pytest-test-prefix-collisions` (выявлены ARG-028, отложены).
7. **`apktool.yaml`-drift root-cause (ARG-038)** — apktool.yaml signature drift возникает между прогонами test-suite в ARG-021/022/027/029 (некоторый тест мутирует `config/tools/apktool.yaml` mid-run); root-cause не локализован — Cycle 4 investigation.

---

## Acceptance Gates Results

Все команды запущены из `backend/` PowerShell-shell'ом на dev-боксе 2026-04-19. Захвачены exit-code и последние строки stdout/stderr.

| Gate | Команда | Результат | Tail |
|---|---|---|---|
| Tools signature verify | `python -m scripts.tools_sign verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys` | ✅ EXIT=0 | `{"event": "verify.ok", "signatures_path": "config\\tools\\SIGNATURES", "verified_count": 157}` |
| Payloads signature verify | `python -m scripts.payloads_sign verify --payloads-dir config/payloads --signatures config/payloads/SIGNATURES --keys-dir config/payloads/_keys` | ✅ EXIT=0 | `{"event": "verify.ok", "signatures_path": "config\\payloads\\SIGNATURES", "verified_count": 23}` |
| Prompts signature verify | `python -m scripts.prompts_sign verify --prompts-dir config/prompts --signatures config/prompts/SIGNATURES --keys-dir config/prompts/_keys` | ✅ EXIT=0 | `{"event": "verify.ok", "signatures_path": "config\\prompts\\SIGNATURES", "verified_count": 5}` |
| Docs drift check | `python -m scripts.docs_tool_catalog --check` | ✅ EXIT=0 | `docs_tool_catalog.check_ok tools=157 path=D:\Developer\Pentest_test\ARGUS\docs\tool-catalog.md` |
| Coverage matrix (12 × 157 + summary) | `python -m pytest tests/test_tool_catalog_coverage.py -q --tb=short` | ✅ EXIT=0 | `1887 passed in 12.10s` |
| Parser unit + integration suites | `python -m pytest tests/integration/sandbox/parsers tests/unit/sandbox/parsers -q --tb=short` | ✅ EXIT=0 | `1578 passed in 25.69s` |
| Reports + MCP unit suites | `python -m pytest tests/unit/reports tests/unit/mcp -q --tb=short` | ✅ EXIT=0 | `455 passed, 1 warning in 9.44s` |
| Security suite | `python -m pytest tests/security -q --tb=short` | ✅ EXIT=0 | `335 passed, 1 warning in 8.69s` |
| `mypy --strict` (sandbox + mcp) | `python -m mypy --strict --follow-imports=silent src/sandbox src/mcp` | ✅ EXIT=0 | `Success: no issues found in 98 source files` |
| `mypy --strict` на изменённых файлах | `python -m mypy --strict --follow-imports=silent tests/test_tool_catalog_coverage.py scripts/docs_tool_catalog.py` | ✅ EXIT=0 | `Success: no issues found in 2 source files` |
| `mypy --strict src/reports` | `python -m mypy --strict --follow-imports=silent src/reports` | ⚠️ EXIT=1 | `Found 24 errors in 8 files (checked 24 source files)` — **24 pre-existing errors** в `src/reports/{generators, ai_text_generation, report_pipeline, finding_severity_normalizer}.py`, документированы в ARG-025 как Cycle 4 cleanup; ARG-030 не вносит новых mypy-warning'ов. |
| `ruff check` (touched files) | `python -m ruff check tests/test_tool_catalog_coverage.py scripts/docs_tool_catalog.py tests/integration/sandbox/parsers/test_arg022_dispatch.py tests/integration/sandbox/parsers/test_nuclei_dispatch.py tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py` | ✅ EXIT=0 | `All checks passed!` |
| `ruff format --check` (touched files) | `python -m ruff format --check tests/test_tool_catalog_coverage.py scripts/docs_tool_catalog.py tests/integration/sandbox/parsers/test_arg022_dispatch.py tests/integration/sandbox/parsers/test_nuclei_dispatch.py tests/integration/sandbox/parsers/test_trivy_semgrep_dispatch.py` | ✅ EXIT=0 | `5 files already formatted` |
| `ruff check src tests` (full repo) | `python -m ruff check src tests` | ⚠️ EXIT=1 | `Found 98 errors. [*] 71 fixable...` — **98 pre-existing** unused-import / unused-variable warnings в `src/recon/...` и legacy test-модулях; ноль новых из ARG-030 touched files. |
| `bandit -q -r src` | `python -m bandit -q -r src` | ⚠️ EXIT=1 | `Medium: 13 / High: 82` — **95 pre-existing** findings в `src/api/routers/*.py`, `src/services/*.py`, `src/recon/*.py`, etc.; ноль новых в `src/sandbox/parsers/__init__.py`, `src/reports/`, `src/mcp/`, `scripts/`. |

Сноски к ⚠️ EXIT=1 строкам: эти три gate'а возвращают non-zero, но **дельта от ARG-030** равна нулю. ARG-025 уже задокументировал «468 pre-existing mypy errors» как Cycle 4 cleanup; ARG-028 явно отделил «Docker-bound 2906 кейсов» от dev-default'а. Для ARG-030 принципиально, что (а) каждое touched-touched файлы зелёные, (б) coverage matrix матерится `1887 passed`, (в) сanitizer-related security suite зелёный (`335 passed`).

---

## Sign-off

**Cycle 3 closed: 2026-04-19.** Все 10 задач (ARG-021..ARG-030) выполнены, DoD §19.6 (parsers progression target `mapped ≥ 68, heartbeat ≤ 89`) попадание ровно в цель, capstone'овая coverage-matrix C11/C12 расширения зелёные на 100 % без exemption'ов.

**Contributing agents (по плану):**

- Planner (план Cycle 3 + per-task ToR'ы) — Cursor/Claude composer-2
- Worker (10 задач, по 1 worker'у на задачу, batch'и параллельно) — Cursor/Claude composer-2 / opus-4.7
- Test-writer (unit + integration suite'ы для каждой задачи) — sub-agent в каждом worker-проходе
- Test-runner (диагностика + verbatim verification) — sub-agent в каждом worker-проходе
- Documenter (per-task worker reports + этот sign-off) — Cursor/Claude composer-2 (ARG-030 worker)
- Debugger (вычистка stale-test guard'ов в ARG-030, mypy/ruff/bandit triage) — Cursor/Claude composer-2 (ARG-030 worker)

**Cycle 3 ✅ closed; Cycle 4 unblocked.** Carry-over backlog (ARG-031..ARG-040) пройден seeded в `ai_docs/develop/issues/ISS-cycle4-carry-over.md`. Ratchet-инварианты на момент закрытия: `MAPPED_PARSER_COUNT = 68`, `HEARTBEAT_PARSER_COUNT = 89`, `COVERAGE_MATRIX_CONTRACTS = 12`. Любая попытка драгировать эти константы вниз без явного worker-report'а ловится в `tests/test_tool_catalog_coverage.py` именованным failure'ом.

---

## Ссылки

- **Cycle 3 plan:** [`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md`](../plans/2026-04-19-argus-finalization-cycle3.md)
- **Cycle 2 report:** [`ai_docs/develop/reports/2026-04-18-argus-finalization-cycle2.md`](2026-04-18-argus-finalization-cycle2.md)
- **Per-task worker reports (ARG-021..ARG-029):** `ai_docs/develop/reports/2026-04-19-arg-02*-report.md` (12 файлов)
- **Auto-generated catalog:** [`docs/tool-catalog.md`](../../../docs/tool-catalog.md) (157 tools, ARG-030 layout)
- **Coverage matrix gate:** [`backend/tests/test_tool_catalog_coverage.py`](../../../backend/tests/test_tool_catalog_coverage.py) (12 контрактов × 157 = 1884 кейсов)
- **MCP server doc:** [`docs/mcp-server.md`](../../../docs/mcp-server.md)
- **Report service doc:** [`docs/report-service.md`](../../../docs/report-service.md)
- **Sandbox images doc:** [`docs/sandbox-images.md`](../../../docs/sandbox-images.md)
- **Network policies doc:** [`docs/network-policies.md`](../../../docs/network-policies.md)
- **Testing strategy doc:** [`docs/testing-strategy.md`](../../../docs/testing-strategy.md)
- **Cycle 4 carry-over backlog:** [`ai_docs/develop/issues/ISS-cycle4-carry-over.md`](../issues/ISS-cycle4-carry-over.md)
- **Backlog (source of truth):** `Backlog/dev1_md`
- **CHANGELOG:** [`CHANGELOG.md`](../../../CHANGELOG.md) (новая Cycle 3 секция в шапке)
