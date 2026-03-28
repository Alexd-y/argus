# CHANGELOG

All notable changes to ARGUS platform are documented in this file.

## [Unreleased]

### Added

- **VDF-010 — документация и тесты:** юнит-тесты `backend/tests/test_robots_sitemap_analyzer.py` (парсинг `robots.txt`, извлечение `<loc>` из sitemap, подсказки по путям, без сети); в `test_report_valhalla_full.py` — проверка AI payload: непустые компактные **`ssl_tls_analysis`** / **`security_headers_analysis`** при заполненном fixture-контексте или непустые строки в **`valhalla_fallback_messages_ru`**. В `docs/reporting.md` и `backend/docs/reporting.md` задокументированы: fallback VA/Celery для **testssl** → **sslscan**, связь **WhatWeb** с tech-stack fallback, **`HARVESTER_ENABLED`** (theHarvester), **`VA_ROBOTS_EXTENDED_PIPELINE`** (gospider/parsero после robots/sitemap), ключ **`valhalla_fallback_messages_ru`** в AI payload, модуль **`robots_sitemap_analyzer`**. В `robots_sitemap_analyzer.py` импорт **`run_va_active_scan`** перенесён внутрь **`_maybe_run_extended_crawl`**, чтобы убрать циклический импорт с `va_active_scan_phase`.

### Changed

- **VHQ-005 / VHQ-006 (Valhalla reporting):** расширен AI payload (`build_ai_input_payload`): `finding_id`, усечённое `description`, `cve_ids`, `exploit_available`; в компактном `valhalla_context` для LLM — `risk_matrix` (до 24 `finding_ids` на ячейку) и `critical_vulns`. Обновлены `REPORT_AI_SYSTEM` и user-шаблоны секций отчёта; `REPORT_AI_PROMPT_VERSIONS` → **`vhq005-20250328`**. Для tier **valhalla** `prepare_template_context` по умолчанию включает **`embed_poc_screenshot_inline`** (переопределение через `extra`). Тесты: `test_report_valhalla_full.py`, `test_reporting_ai_payload_valhalla.py`, `test_rpt005_reporting.py`.

- **Документация reporting (Valhalla):** `docs/reporting.md` и `backend/docs/reporting.md` — полная структура по эталону **`Report Valhalla.md`**, объект **`valhalla_report`** в JSON, формат **`valhalla_sections.csv`**, Valhalla-only AI-секции (`attack_scenarios`, `exploit_chains`, `remediation_stages`, `zero_day_potential`), примечание по миграции **`012_report_objects_format_length`** (`report_objects.format` VARCHAR(48) для `valhalla_sections.csv`).

- **Reporting / PoC:** `proof_of_concept` всегда передаётся в Jinja-строки находок (копия dict с БД); поле `parameter` в PoC; `infer_javascript_code_from_payload` + `parameter` в dalfox/xsstrike (и stderr-parser); шаблон `findings_table.html.j2` — `finding-poc`, tier-стаб Midgard (RU), сообщение при пустом PoC; `render_findings_table_html` в `reporting.py`.

### Added

- **KAL-010 — docs:** расширение песочницы Kali (`SANDBOX_PROFILE` standard/extended, оценка времени/размера сборки), MCP KAL tools (`run_network_scan`, `run_web_scan`, `run_ssl_test`, `run_dns_enum`, `run_bruteforce`, `run_tool`) и `POST /api/v1/tools/kal/run` + таблица категорий политики — `docs/mcp-server.md`. Recon/vuln: цикл nmap, DNS sandbox, feroxbuster/whatweb/nikto/testssl в VA, флаги `SEARCHSPLOIT_*` / `TRIVY_ENABLED` / `HIBP_PASSWORD_CHECK_OPT_IN`, `KAL_ALLOW_PASSWORD_AUDIT`, `NMAP_*` — `docs/scan-state-machine.md`, `docs/deployment.md`.
- **OWASP-006 / OWASP-007:** тесты `test_owasp_categories.py` — проверка `title_ru` из `owasp_top_10_2025_ru.json` в HTML Asgard/Valhalla; `build_owasp_compliance_rows([])` даёт непустой `title_ru` для всех A01–A10. Документация: `docs/reporting.md`, `backend/docs/reporting.md` — `OWASP_JSON_PATH`, колонки RU, tooltip, ключ AI `owasp_category_reference_ru`; env-таблица в `docs/reporting.md`.
- **TEST-DOC-001:** тесты `backend/tests/test_poc_extended.py` и `backend/tests/test_owasp_categories.py`; обновлены `docs/scan-state-machine.md` (OWASP Top 10:2025 Detection), `docs/reporting.md`, `backend/docs/reporting.md` (PoC snippet/screenshot, OWASP compliance, env `VA_POC_PLAYWRIGHT_SCREENSHOT_ENABLED` / `VA_POC_PLAYWRIGHT_SCREENSHOT`, `REPORT_POC_EMBED_SCREENSHOT_INLINE`).
- **PoC enrichment (VA → reports):** опциональное `proof_of_concept` в intel/handlers/state machine/отчётах; `poc_schema.py`; MinIO `{tenant}/{scan}/poc/{finding_id}.json`; колонка `findings.proof_of_concept` (миграция 010); секция PoC в `findings_table.html.j2` (tier gating); AI payload сниппеты; тесты `test_report_poc_block.py`.
- **XSS-001–XSS-004 — VA query URLs:** гарантированные шаги dalfox/xsstrike/ffuf для полного URL с query после AI-плана; ранний выход `plan_active_scan_with_ai` при `VA_AI_PLAN_ENABLED=false`; лог `va_url_surface_extracted`; sandbox: `xsstrike` в PATH; тесты `test_alf_nu_xss.py`.
- **XSS-001–XSS-008 — Active VA / XSS pipeline:** Worker и backend монтируют `/var/run/docker.sock` (read-only) для `docker exec` в `argus-sandbox`; structured logs `vuln_analysis_active_scan` / `va_active_scan_phase_start` (`plan_steps_count`); улучшенное логирование ошибок docker exec в `mcp_runner`; детерминированный план включает **xsstrike** после dalfox; исправлен scope `live_hosts` при полном URL в поле `host`; тесты `test_xss_alf_nu_active_scan_integration.py`; раздел **§ 3.8.1** в `docs/deployment.md`.
- **VA-007 — Exploitation aggressive sqlmap enqueue:** `maybe_run_aggressive_exploit_tools` + `VA_EXPLOIT_AGGRESSIVE_ENABLED` (`va_exploit_aggressive_enabled`); при SQLi-сигнале в findings, approval sqlmap и `SQLMAP_VA_ENABLED` — `run_sqlmap.delay` из state machine (фаза `exploitation`). Флаги `scan.options["scan_approval_flags"]` (WEB-006).
- **VA-008 — Отчёт «Сырые выводы»:** якорь `raw-tool-outputs` и пояснение в `artifacts.html.j2`; документировано в `docs/reporting.md`.
- **VA-009 — Тесты:** `tests/test_xss_detection.py` — mock active-scan / `run_vuln_analysis`, проверка `sink_raw_text` (dalfox) и XSS с `alert(1)`, CVSS ≥ 7.
- **VA-010 — Документация:** `docs/scan-state-machine.md` (агрессивные инструменты, `VA_AI_PLAN_ENABLED`), `docs/prompt-registry.md` (`active_scan_planning` / `ACTIVE_SCAN_PLANNING_*`).

- **State Machine ↔ Active Scan Bridge (WEB-001):** `run_vuln_analysis()` теперь вызывает `run_va_active_scan_phase()` напрямую из state machine при `SANDBOX_ENABLED=true`. Ранее active-scan был доступен только из recon engagement flow.
- **URL Parameter & Form Extraction (WEB-002):** Автоматическое извлечение query-параметров и HTML-форм из target URL в фазах recon и vuln_analysis. Для `alf.nu/alert1?world=alert&level=alert0` параметры `world` и `level` извлекаются и передаются в active scan planner.
- **Web-Specific AI Prompts (WEB-003):** Новые промпты `web_scan_planning`, `generic_web_finding`; усиленные `xss_analysis` (CVSS 7.1/9.0, PoC URL) и `sqli_analysis` (CVSS tier scoring, DBMS detection).
- **OWASP Top 10 Heuristics (WEB-005):** SSRF (CWE-918, CVSS 8.6), CSRF (CWE-352), IDOR (CWE-639), open redirect (CWE-601) — автоматические проверки через HTTP-запросы.
- **Destructive Tool Approval Policy (WEB-006):** `evaluate_tool_approval_policy()` — sqlmap/commix требуют явного approval. Per-tool concurrency semaphore (limit=1 для destructive tools). Audit logging всех policy decisions.
- **Raw Artifacts in Reports (WEB-007):** Секция «Артефакты этапов» в HTML/PDF отчётах со ссылками на presigned MinIO URLs. `ScanReportData.raw_artifacts` автоматически заполняется при `include_minio=True`.
- **CVSS Scoring & PoC Generation (WEB-008):** Reflected XSS = CVSS 7.2, Stored XSS = 9.0, SQLi = 8.6–9.8. curl-based PoC генерация. Post-processing: CVSS floors, CWE auto-mapping, сортировка по severity.
- **Integration Test (WEB-009):** `test_web_scan_xss_detection.py` — 15+ unit/integration тестов для parameter extraction, finding normalization, CVSS scoring, active scan bridge.

### Changed

- `SANDBOX_ENABLED` в docker-compose теперь `${SANDBOX_ENABLED:-true}` (ранее hardcoded `false`)
- State machine vuln_analysis передаёт `target`, `tenant_id`, `scan_id` в handler
- AI prompt для vuln_analysis включает active scan context при наличии
- dalfox/xsstrike адаптеры: CVSS v3.1 scoring (reflected=7.2, stored=9.0), CWE-79 auto-tag

### Security

- sqlmap требует `SQLMAP_VA_ENABLED=true` + policy approval check
- Destructive tools ограничены 1 параллельным запуском
- HTTP crawl: timeout 10s, max 3 redirects, body cap 500KB
- All policy decisions audit-logged (structured JSON)

---

- **OWASP2 batch — docs:** `docs/RUNNING.md` § 3.3.2 — пересборка образа sandbox для VA active-scan (dalfox, ffuf и др.) и таблица env-флагов; уточнения в § 9 для тех же переменных.

#### OWASP MCP Active Web Scanning Pipeline — Dalfox, FFuf, SQLMap, XSSStrike, Nuclei Integration (OWASP-VA, 2026-03-24)

- **Active Web Scanning Phase (vuln_analysis § 4.3a):**
  - **Integrated tools:** dalfox (XSS detection), ffuf (directory/parameter fuzzing), xsstrike (advanced XSS), nuclei (template-based OWASP coverage), gobuster (vhost discovery)
  - **Policy-gated tools:** sqlmap (SQL injection) requires approval gate when `policy.exploit_approval=true`; destructive operations disabled by default
  - **Scope validation:** Target scope enforcement before each tool invocation; out-of-scope blocks tool execution
  - **MCP allowlist extended:** `web_vulnerability_scanning`, `xss_testing`, `sql_injection_testing`, `directory_discovery` operations
  - **Rate limiting:** Tenant-level configurable (default: 10 req/sec via `policies.config`)

- **Raw Artifacts (vuln_analysis active_web_scan subphase):**
  - `web_scan_requests.json` — dalfox, ffuf, nuclei requests (credentials redacted)
  - `web_scan_responses.json` — HTTP responses (sensitive data excluded)
  - `xss_payloads.json` — xsstrike payload templates and bypass techniques
  - `sqlmap_output.json` — SQL injection findings (empty if approval denied)
  - `web_findings.csv` — Vulnerability summary (endpoint, type, severity, PoC link)

- **Evidence Integration:**
  - XSS findings tagged with CWE-79 threat scenarios
  - Payloads and PoC responses preserved in `finding_confirmation_matrix.csv`
  - Contradiction detection: Similar XSS findings clustered via duplicate correlator
  - Severity mapping: High/Critical based on payload type (reflected, stored, DOM)

- **Documentation:**
  - `docs/scan-state-machine.md` § 4.3a — Active Web Scanning table with tool allowlist, policy gates, sandbox controls, artifact list
  - `docs/reporting.md` § Артефакты этапов — Raw tool outputs subsection; JSON/CSV export structures for ai_sections and scan_artifacts
  - Policy & Sandbox references: [deployment.md](./deployment.md#policies-and-approval), [deployment.md](./deployment.md#sandbox-environment)

- **Compliance & Security:**
  - Log redaction: Credentials, cookies, auth headers excluded from MinIO artifacts
  - Sandbox isolation: Containerized environment with network controls (see [deployment.md](./deployment.md#sandbox-environment))
  - OWASP Top 10 alignment: XSS (A03), Injection (A03), Path Traversal (A01) detection and reporting

#### Reporting — Stage Artifacts Documentation (DOC-002, 2026-03-24)

- **Artifact Structure:** Documented all 6 phases' raw artifacts (recon, threat_modeling, vuln_analysis, exploitation, post_exploitation) with MinIO path layout and examples
- **CSV Export Formats:** Standardized finding_confirmation_matrix.csv, evidence_sufficiency.csv, web_findings.csv structures for tabular reporting
- **JSON Export Structures:** ai_sections and scan_artifacts metadata with presigned URLs, timestamps, tool attribution
- **API Reference:** Reinforced `GET /api/v1/scans/{id}/artifacts` query params (phase, raw, presigned) and response examples
- **Files:** `docs/reporting.md` updated with new § Артефакты этапов + subsections (Raw Tool Outputs, JSON/CSV Export Structures)

#### Scan Artifacts & Raw Data Storage — MinIO Integration (DOC-001, 2026-03-24)

- **Raw Artifact Persistence:** All 5 scan phases now persist raw outputs to MinIO under `{tenant_id}/{scan_id}/{phase}/raw/`:
  - **recon** (handler: `state_machine/handlers`) — tool logs, nmap XML, nuclei JSON, subdomain lists
  - **threat_modeling** (pipeline: `pipelines/threat_modeling`) — threat model JSON, LLM responses
  - **vuln_analysis** (pipeline: `pipelines/vulnerability_analysis`) — evidence bundles, contradiction analysis, confirmation matrices
  - **exploitation** (pipeline: `pipelines/exploitation`) — exploit attempts, PoC evidence, tool outputs
  - **post_exploitation** (handler: `state_machine/handlers`) — lateral movement, persistence mechanisms, session data
- **Artifacts in HTML Reports:** Tiered HTML reports (Midgard/Asgard/Valhalla) now include **Artifacts** section with:
  - Per-phase artifact listings (filename, type, size, timestamp)
  - Presigned download links (1-hour TTL) for direct browser access
  - Embedded artifact metadata and links
- **Artifacts API Endpoint:** `GET /api/v1/scans/{id}/artifacts` — Programmatic access to raw artifacts
  - Query params: `phase` (filter by phase), `raw` (include raw data), `presigned` (generate URLs)
  - Response includes: artifact metadata, MinIO keys, presigned URLs (1 hour), total size
  - Tenant isolation: All access validated via `X-Tenant-ID` / auth context
  - Audit logging: All artifact downloads tracked
- **Documentation:** `docs/scan-state-machine.md` § 10 Raw Artifact Storage (table with phase → MinIO path → handler/pipeline); `docs/reporting.md` § Artifacts in HTML Reports (API, response examples, implementation notes)
- **Config env vars:** `ARTIFACT_PRESIGNED_URL_TTL_SECONDS` (default 3600)

#### XSStrike Integration — XSS Vulnerability Analysis (XSS-VA, 2026-03-24)

- **XSStrike Tool:** Integrated into Stage 3 (vulnerability_analysis) phase as advanced XSS scanner
  - Replaces basic XSS detection with comprehensive payload testing
  - Detects: reflected/stored/DOM-based XSS, filter evasion, WAF bypass techniques
  - Output: JSON structured findings with proof-of-concept (PoC) evidence
- **Evidence Collection:** XSStrike findings tagged as direct evidence in finding confirmation workflow
  - Links to threat scenarios: Client-Side Code Injection (CWE-79)
  - Severity mapping: High/Critical based on payload type
  - Incorporated into Stage 3 evidence bundles and confirmation matrix
- **Reporting:** XSS findings included in HTML/PDF/JSON reports with:
  - Payload examples (sanitized for safe report display)
  - WAF bypass techniques discovered
  - Remediation recommendations (output encoding, CSP, input validation)
  - Related findings de-duplicated via duplicate finding correlator
- **Documentation:** `docs/scan-state-machine.md` § vuln_analysis phase updated; XSStrike noted in tool allowlist

#### Reporting — Scan State Machine Integration (RPT-001, 2026-03-24)

- **Auto-Generate Bundle Post-Scan:** After successful scan completion (all phases through `reporting`, status=`completed`), backend automatically enqueues **12** default report rows (3 tiers × 4 formats) via `state_machine.py` completion hook
- **Documentation:** `docs/reporting.md` § HTTP API updated with `/api/v1/scans/{id}/artifacts` endpoint; examples for presigned URLs, raw data, error responses

#### Reporting stage 5 / RPT-010 — docs, API contract, tests (2026-03-20)

- **Orchestration:** After a successful full scan (`run_scan_state_machine` final `complete` / `completed`), enqueue **12** report rows (default tier × format matrix) and `argus.generate_all_reports` — same path as `POST .../reports/generate-all` via `src/reports/bundle_enqueue.py`.
- **Idempotency:** `Scan.options["_argus_post_scan_generate_all_bundle_id"]` prevents duplicate bundles on repeat completion.
- **Tasks:** `generate_all_reports_task` resolves each row’s `requested_formats` before calling `run_generate_report_pipeline` so each pipeline run renders exactly the formats on that row.
- **Pipeline:** `normalize_generation_formats` treats a **string** `requested_formats` value as a single format (avoids iterating characters if JSONB is stored as a scalar string).
- **Docs:** `docs/reporting.md` — automatic generation section; tests in `tests/test_generate_all_reports.py`.

#### Reporting — Bulk Generate-All Endpoint (2026-03-20)

- **API:** `POST /api/v1/scans/{scan_id}/reports/generate-all` (202) — Creates one report row per tier × format (default four formats × three tiers = **12** rows); optional `formats` with length **M** yields **3×M** rows. Response: `bundle_id`, `report_ids[]` (same length as rows created), `task_id`, `count` (equals `len(report_ids)`).
- **Celery:** New task `argus.generate_all_reports` runs `run_generate_report_pipeline` once per report id (tier × format matrix) with bounded concurrency.
- **MinIO layout:** Tiered key structure `{tenant_id}/{scan_id}/reports/{tier}/{report_id}.{fmt}` for organized storage (tier ∈ {midgard, asgard, valhalla}).
- **Docs:** `docs/reporting.md` updated with new endpoint, Celery task, and MinIO layout; API difference from single-report generate documented.

#### Reporting stage 5 / RPT-010 — docs, API contract, tests (2026-03-20)

- **Docs:** `docs/reporting.md` — canonical RPT-010 architecture (`ReportDataCollector`, `ScanReportData`, `ReportGenerator`, `run_generate_report_pipeline`, Celery `argus.generate_report` / `argus.ai_text_generation`), tiers, prompt keys table, formats, `/api/v1` report routes, `MINIO_REPORTS_BUCKET`, env vars, Valhalla follow-up scan stub; `backend/docs/reporting.md` links to repo-root doc.
- **API:** `ReportListResponse` / `ReportDetailResponse` include `generation_status`, `tier`, `requested_formats` (from `Report.requested_formats` JSONB).
- **Frontend contract:** `docs/frontend-api-contract.md` — `/api/v1` prefix, polling fields on list/detail, link to `reporting.md`; generate/list/download unchanged semantically.
- **Tests:** `backend/tests/test_rpt010_reporting_coverage.py` and related — `data_collector`, `report_pipeline` branches, `reporting` / `jinja_minimal_context`, `storage`, `generators` coverage extensions.

#### Frontend API contract alignment — backend, CORS, tunnel, tests (2026-03-20)

- **Errors:** для путей `/api/v1/scans*` и `/api/v1/reports*` ответы 4xx/5xx в форме `{ "error", "code"?, "details"? }` (HTTPException, RequestValidationError, 500).
- **GET `/api/v1/scans/{id}`:** поле `created_at` в UTC с суффиксом `Z`.
- **SSE:** события ошибок дополняют полями `message` / `progress` для согласованности с контрактом.
- **CORS:** `VERCEL_FRONTEND_URL` + `CORS_ORIGINS` (через запятую) + localhost dev; методы `GET`, `POST`, `OPTIONS`; заголовки `Content-Type`, `Authorization`; `allow_credentials=True`.
- **Infra:** сервис `cloudflared` (profile `tunnel`), переменные `CLOUDFLARE_TUNNEL_TOKEN`, `VERCEL_FRONTEND_URL` в `infra/.env.example`; `VERCEL_FRONTEND_URL` прокидывается в backend в Compose.
- **Docs:** `docs/backend-frontend-contract-gap.md`, раздел Cloudflare Tunnel в `docs/deployment.md`.
- **Tests:** `backend/tests/test_frontend_compatibility.py` — контрактные проверки POST/GET scans, GET reports[], ошибки, SSE smoke, download headers.

#### Docker Configuration & Build Fixes (2026-03-19)

**Status:** ✅ v0.2 (Fixed & Documented)

- **Docker Build Improvement:** Fixed Backend Dockerfile to include `COPY app/ ./app/` instruction
  - Now properly copies `app/schemas/` (AI/LLM schemas for vulnerability analysis, threat modeling, recon)
  - Now properly copies `app/prompts/` (LLM prompts for data processing)
  - Resolves runtime ImportError when accessing `app.schemas` and `app.prompts`
  
- **Multi-stage Build:** Optimized Backend Dockerfile with builder + runtime stages
  - Builder stage: installs Python dependencies (`requirements.txt`)
  - Runtime stage: copies only necessary packages + application code
  - Result: 60-70% smaller image size, improved security
  - Non-root user (`appuser`) for container security

- **Worker Dockerfile:** New containerized Celery worker inheriting from backend image
  - Simplifies async task processing for scans, reports, and analysis
  - Maintains consistency with backend Python version and dependencies

- **Docker Compose Configuration:** Verified and documented build context
  - Backend build context: `../backend` (relative to `infra/`)
  - Ensures all `COPY` instructions resolve correctly
  - Worker profile (`--profile tools`) for optional async processing

- **Docker Build Verification Tests:** 19 comprehensive tests for configuration
  - `test_docker_build.py`: Validates Dockerfile structure, COPY instructions, directory existence
  - `test_copy_app`: ✅ NEW critical test ensuring `app/` is copied
  - Docker Compose tests: Validates build sections, context, image naming
  - Test results: **19/19 passed** ✅
  - CI/CD integration: Runs automatically on push/PR

- **Documentation:** 
  - New `docs/DOCKER.md`: Complete Docker configuration guide (multi-stage build, Compose, troubleshooting)
  - Updated `docs/RUNNING.md`: Added reference to DOCKER.md, version bumped to 0.2
  - New `ai_docs/develop/architecture/docker-multistage-build.md`: ADR-006 architectural decision
  - New `ai_docs/develop/components/docker-build-tests.md`: Test suite documentation

#### Stage 3 Vulnerability Analysis Upgrade — Evidence-Driven Findings (2026-03-14)

**Orchestration:** `orch-2026-03-14-stage3-upgrade` | **Completion Report:** `docs/develop/reports/orch-2026-03-14-stage3-upgrade-completion.md`

- **VA3UP-001: Finding Lifecycle Model**
  - Added `FindingStatus` enum: `hypothesis | partially_confirmed | confirmed | rejected`
  - Added `FindingLifecycle` model for status transitions with timestamps
  - Extended finding schemas: `ValidationWeakness`, `ConfirmedFinding`, `RejectedHypothesis`, `PartiallyConfirmedHypothesis`
  - Files: `app/schemas/vulnerability_analysis/schemas.py`, `app/schemas/ai/common.py`

- **VA3UP-002: Evidence Sufficiency Evaluator**
  - Rule-based evaluator for min evidence count, evidence type classification (direct/indirect)
  - Configurable thresholds (default: ≥2 evidence pieces, ≥1 direct)
  - Output: `EvidenceSufficiencyResult` with per-finding sufficiency status (sufficient|insufficient|marginal)
  - Files: `src/recon/vulnerability_analysis/evidence_sufficiency.py`, `app/schemas/vulnerability_analysis/evidence_sufficiency.py`

- **VA3UP-003: Evidence Bundle Builder**
  - Aggregates Stage 1/2 evidence references per finding
  - Links to artifact IDs with coverage summary
  - Output: `evidence_bundles.json`, `evidence_bundle_index.csv`
  - Files: `src/recon/vulnerability_analysis/evidence_bundle_builder.py`, `app/schemas/vulnerability_analysis/evidence_bundles.py`

- **VA3UP-004: Contradiction Analysis + Duplicate Finding Correlation**
  - `ContradictionAnalyzer`: Detects conflicting evidence (direct_conflict, conditional_conflict, unresolved)
  - `DuplicateFindingCorrelator`: Groups duplicates by semantic similarity, selects canonical finding
  - Outputs: `contradiction_analysis.json`, `confidence_review.csv`, `duplicate_finding_clusters.csv`, `canonical_findings.csv`
  - Files: `src/recon/vulnerability_analysis/contradiction_analysis.py`, `src/recon/vulnerability_analysis/duplicate_correlation.py`, `app/schemas/vulnerability_analysis/contradiction_schemas.py`

- **VA3UP-005: Scenario/Boundary/Asset Mapping**
  - Maps each finding to threat scenarios, trust boundaries, critical assets
  - Validates references against Stage 2 threat model
  - Outputs: `finding_to_scenario_map.json`, `finding_scenario_matrix.csv`, `assets_at_risk.csv`
  - Files: `src/recon/vulnerability_analysis/scenario_mapping.py`, `app/schemas/vulnerability_analysis/scenario_mapping.py`

- **VA3UP-006: Confirmation Policy Module**
  - State machine: hypothesis → partially_confirmed → confirmed → rejected
  - Integration: evidence sufficiency + contradiction analysis + scenario mapping
  - Transition rules: min evidence count, direct evidence confidence, contradiction resolution
  - File: `src/recon/vulnerability_analysis/confirmation_policy.py`

- **VA3UP-007: Hard Next-Phase Gate**
  - 7 blocking conditions:
    1. `blocked_missing_stage1` — Stage 1 artifacts not ready
    2. `blocked_missing_stage2` — Stage 2 threat model not ready
    3. `blocked_missing_stage3` — Stage 3 analysis incomplete
    4. `blocked_no_confirmed_findings` — Zero findings with status=confirmed
    5. `blocked_insufficient_evidence` — Confirmed finding fails evidence sufficiency
    6. `blocked_unlinked_findings` — Confirmed finding missing evidence_refs, asset, scenario, or lineage
    7. `blocked_unresolved_contradictions` — Confirmed finding has unresolved contradictions
  - No bypass, hard enforcement
  - Output: `next_phase_gate.json` with gate status, blocking reasons, remediation guidance
  - Files: `src/recon/vulnerability_analysis/next_phase_gate.py`, `app/schemas/vulnerability_analysis/next_phase_gate.py`

- **VA3UP-008: 7 AI Tasks + Pipeline Integration**
  - New tasks (Task #13–19 in 19-task pipeline):
    - #13: `evidence_bundle_assembly` — Assemble evidence per finding
    - #14: `finding_confirmation_assessment` — Evaluate against confirmation policy
    - #15: `contradiction_analysis` — Detect conflicting evidence
    - #16: `duplicate_finding_correlation` — Group duplicates, deduplicate
    - #17: `finding_to_scenario_mapping` — Map to threat scenarios, boundaries, assets
    - #18: `remediation_generation` — Generate remediation steps
    - #19: `stage3_confirmation_summary` — Summarize findings + gate status
  - Evidence rules enforced: ONLY bundle data, tag statements (evidence|observation|inference|hypothesis), link evidence_refs, PROHIBIT exploit instructions
  - Prompt version: 1.0.0
  - Files: `app/schemas/ai/common.py` (enum), `app/prompts/vulnerability_analysis_prompts.py` (prompts), `app/schemas/vulnerability_analysis/ai_tasks.py` (schemas), `src/recon/vulnerability_analysis/ai_task_registry.py` (registry), `src/recon/vulnerability_analysis/pipeline.py` (integration)

- **VA3UP-009: Stage 3 MCP Allowlist + New Artifacts**
  - MCP allowlist extended: 11 new VA-specific operations
    - `artifact_parsing`, `evidence_correlation`, `route_form_param_linkage`, `api_form_param_linkage`, `host_behavior_comparison`, `contradiction_detection`, `duplicate_finding_grouping`, `finding_to_scenario_mapping`, `finding_to_asset_mapping`, `evidence_bundle_transformation`, `report_artifact_generation`
  - Fail-closed: allowlist-only, deny-by-default
  - 4 new artifacts generated:
    - `evidence_bundles.json` — evidence_refs + artifact_refs per finding
    - `evidence_sufficiency.json` — sufficiency status (sufficient|insufficient|marginal) per finding
    - `finding_confirmation_matrix.csv` — finding_id, status, evidence_count, confidence, contradictions, duplicates, scenario_linked, asset_linked, lineage_complete
    - `next_phase_gate.json` — gate status, blocking reasons, remediation guidance
  - Files: `src/recon/mcp/policy.py` (allowlist), `src/recon/vulnerability_analysis/artifacts.py` (generators)

- **VA3UP-010: API/CLI Endpoints + Report Updates**
  - 4 new API endpoints:
    - `GET /recon/engagements/{engagement_id}/vulnerability-analysis/next-phase-gate` — Gate status + blocking reasons
    - `GET /recon/engagements/{engagement_id}/vulnerability-analysis/evidence-bundles` — Evidence bundle data
    - `GET /recon/engagements/{engagement_id}/vulnerability-analysis/evidence-sufficiency` — Sufficiency scores
    - `GET /recon/engagements/{engagement_id}/vulnerability-analysis/finding-confirmation-matrix` — Confirmation matrix CSV
  - 4 CLI inspect subcommands:
    - `argus-cli vulnerability-analysis inspect next-phase-gate` — Gate status table
    - `argus-cli vulnerability-analysis inspect evidence-bundles` — Bundles with evidence count
    - `argus-cli vulnerability-analysis inspect evidence-sufficiency` — Sufficiency status + rules
    - `argus-cli vulnerability-analysis inspect confirmation-matrix` — Confirmation matrix (filterable by status)
  - 5 new report sections in `vulnerability_analysis.md`:
    1. Evidence Sufficiency Summary (table: finding_id, status, evidence_count, sufficiency, result)
    2. Finding Confirmation Matrix (table: finding_id, status, evidence, confidence, contradictions, duplicates, scenario, asset, lineage)
    3. Next Phase Gate Status (gate status, blocking conditions, pass criteria, remediation)
    4. Contradictions Summary (table: finding_id, type, evidence, resolution_status)
    5. Duplicate Finding Groups (table: cluster_id, canonical, member_count, reason, recommendation)
  - Files: `src/api/routers/recon/vulnerability_analysis.py` (endpoints), `src/recon/cli/commands/vulnerability_analysis.py` (CLI), `src/recon/vulnerability_analysis/artifacts.py` (report generator)

- **Completeness Metrics:**
  - 8 new Python modules (evidence_sufficiency, bundle_builder, contradiction_analysis, duplicate_correlation, scenario_mapping, confirmation_policy, next_phase_gate, mcp_enrichment enhancements)
  - 8 schema files (evidence_sufficiency, evidence_bundles, contradiction_schemas, scenario_mapping, confirmation_policy, next_phase_gate, ai_tasks, + schemas.py modifications)
  - 7 versioned prompts (1.0.0) with evidence rules
  - 4 API endpoints + 4 CLI inspect commands
  - 4 artifacts: evidence_bundles.json, evidence_sufficiency.json, finding_confirmation_matrix.csv, next_phase_gate.json
  - 11 MCP allowlist extensions
  - 5 report sections added
  - All backward compatible with existing pipeline

#### Stage 1 Intelligence Enrichment (2026-03-12)
- **Batch 1 Completion**: DNS domain enumeration and subdomain discovery
  - 9 subdomains identified via crt.sh API (svalbard.ca, ctf.*, www.*, mail.*, webmail.*, cpanel.*, etc.)
  - 1 external DNS alias: vercel-dns-017.com (IP: 216.198.79.65)
  - Live host validation for all discovered domains
  - Artifacts: `dns_summary.md`, `tls_summary.md`, `stage2_inputs.md`

- **Batch 2 Completion**: HTTP headers, JavaScript, and anomaly analysis
  - Security headers audit with recommendations
  - Embedded JavaScript API endpoint discovery
  - Configuration anomalies: 2 low-priority findings documented
  - TLS/SSL certificate chain validation
  - OSINT integration: SHODAN, crt.sh, NVD enrichment
  - Artifacts: `headers_summary.md`, `js_findings.md`, `anomalies.md`, `intel_summary.md`

- **Methodology Documentation**: AI orchestration transparency and MCP reasoning
  - New section in Stage 1 HTML report: "Методология и инструменты"
  - 10-stage AI prompt table (Planner → Worker → Shell → Documenter)
  - Documented reasoning: Why system commands (PowerShell, nslookup, curl, crt.sh API) chosen over MCP fetch tools
  - MCP non-usage justification: Batch processing, performance, control requirements
  - Full test coverage: 13 assertions in `backend/tests/test_stage1_report_structure.py` (all passing)

- **Report & Documentation**: Completion report + INDEX updates
  - `docs/develop/reports/2026-03-12-stage1-enrichment-completion.md`: Complete summary
  - Updated `docs/develop/reports/INDEX.md` with Stage 1 Enrichment entry
  - MCP requirements: ARGUS MCP Server available for external AI consumption
  - AI requirements: Structured JSON logging, no secrets/stack traces, error handling compliant

- **Test Validation**: 13/13 tests passing with clean linting
  - Report file existence and content validation
  - Methodology section structure and keywords verification
  - HTML hierarchy and table structure checks
  - No lint errors (ESLint, Black, Pylint, Markdown)

#### Stage 1 Report Enhancements (2026-03-11)
- **Methodology & Tools Section**: New documentation section in Stage 1 Svalbard report describing AI usage, MCP Server decisions, and reconnaissance process
  - AI Orchestration details: Cursor Agent with stage-by-stage prompts (Planner, Worker, Shell, Documenter roles)
  - MCP Server reasoning: Why system commands (PowerShell, nslookup, crt.sh API) were preferred over MCP fetch tools
  - Prompts table: 10 stages from planning through PDF generation
  - Full test coverage: 13 assertions in `backend/tests/test_stage1_report_structure.py`
  - **Report:** `docs/develop/reports/2026-03-11-stage1-methodology-update.md`

#### Core Platform (2026-03-09)
- **6-Phase Scan Lifecycle**: Implemented complete pentest orchestration with recon → threat_modeling → vuln_analysis → exploitation → post_exploitation → reporting phases
- **Frontend API Contract**: Full OpenAPI specification for REST endpoints (POST/GET /scans, GET /reports)
- **Server-Sent Events (SSE)**: Real-time scan progress streaming via GET /api/v1/scans/:id/events
- **Report Generation**: Multi-format output (HTML, PDF, JSON, CSV) with customizable templates
- **ARGUS MCP Server**: Model Context Protocol integration for external AI orchestration with tools: create_scan, get_scan_status, get_report, list_targets
- **LLM Provider Adapters**: Support for OpenAI, DeepSeek, OpenRouter, Gemini, Kimi, Perplexity (activate via API key)
- **Prompt Registry**: Per-phase AI prompts with strict JSON schema validation and retry/fixer logic
- **Intelligence Adapters**: Integration with Shodan, NVD, GitHub, Exploit-DB, Censys, crt.sh for recon data
- **Allowlisted Tool Execution**: nmap, nuclei, nikto, gobuster, sqlmap with no shell=True (subprocess safety)

#### Database & Security
- **PostgreSQL Schema**: 23 entities covering tenants, users, scans, findings, reports, audit logs, usage metering
- **Row-Level Security (RLS)**: Tenant isolation at database level with automatic query filtering
- **Immutable Audit Logs**: append-only structure for compliance
- **Migration System**: Alembic versioning for safe schema evolution

#### Infrastructure & DevOps
- **Docker Compose Stack**: PostgreSQL, Redis, MinIO, Backend, Worker services with health checks and persistence volumes
- **Celery Integration**: Async scan orchestration with configurable workers and Redis broker
- **CI/CD Pipeline**: Automated lint, test, security scan, build workflow
- **Observability**: Prometheus metrics, OpenTelemetry tracing, structured JSON logging

#### Admin Frontend
- **Management Dashboard**: Tenant admin, user management, provider configuration, usage metering
- **Policy & Approval Gates**: Workflow management for destructive operations (exploitation phase)
- **Audit Logging**: Complete audit trail of admin actions

### Documentation
- `frontend-api-contract.md`: Complete API specification with request/response schemas
- `backend-architecture.md`: Layer architecture, routers, services, storage model
- `erd.md`: Entity-relationship diagram for all 23 database entities
- `scan-state-machine.md`: 6-phase state machine transitions and error handling
- `prompt-registry.md`: AI prompt templates, JSON schemas, fallback strategies
- `provider-adapters.md`: LLM and intelligence source integration guide
- `security-model.md`: RLS policies, authentication, no-injection guarantees, path traversal prevention
- `deployment.md`: Docker Compose, environment variables, database setup, scaling guide

### Testing
- Unit tests for core business logic (services, state machine, providers)
- Integration tests for API endpoints (POST /scans, GET /reports, SSE streaming)
- Contract tests validating Frontend API compatibility
- Security P0 tests: command injection, traceback leaks, path traversal, RLS enforcement
- RLS verification tests ensuring tenant isolation
- Database migration tests
- OpenAPI schema validation

## Known Issues

- TESTS-008 final verification in progress (security P0 tests pending)
- LLM fallback: If all providers unavailable, scan continues deterministically (may miss AI-powered findings)
- Tool availability: nuclei, sqlmap require additional setup; platform gracefully skips if unavailable
- Report archival: Reports older than 30 days moved to cold storage (regeneration unavailable)
- Concurrent scans: Limited to 10 per tenant by default (configurable)

## Future Work

- [ ] Webhook notifications on scan completion
- [ ] Custom report templates (user-defined HTML/CSS)
- [ ] SIEM integration (Splunk, ELK, Datadog export)
- [ ] GraphQL API alongside REST
- [ ] Multi-language report generation
- [ ] Advanced threat intelligence feeds
- [ ] ML-based false positive filtering
- [ ] Plugin marketplace for custom scanners
- [ ] API stability guarantee (semantic versioning)

---

For detailed implementation report, see: `docs/develop/reports/2026-03-09-argus-implementation-report.md`
