# План: ARGUS Web Security Workbench (Burp Pro / DAST паритет)

**Created:** 2026-07-22
**Orchestration:** orch-2026-07-22-web-workbench
**Goal:** Внедрить в ARGUS нативный Web Security Workbench с функциональным паритетом
публично документированных возможностей Burp Suite Professional / DAST и наиболее
полезных расширений BApp Store, переиспользуя существующую архитектуру (pipeline,
sandbox, MCP, PayloadRegistry, PromptRegistry, playbooks, Nuclei, OAST, evidence,
reporting). Все активные операции привязаны к verified in-scope assets и подписанному
Engagement Authorization Profile (EAP).

> Это НЕ копирование Burp Suite, его UI, торговых марок или закрытого кода. Реализуется
> поведенческий паритет нативными средствами ARGUS. Каждое заимствование идей фиксируется
> с provenance (repo URL, commit SHA, license, NOTICE).

---

## 0. СТАТУС-ЛЕГЕНДА

| Токен | Значение |
|-------|----------|
| `missing` | Не реализовано, нет кода. |
| `partial` | Частично реализовано / есть только каркас / за feature-flag с fail-closed. |
| `implemented` | Код есть, покрыт unit-тестами, но нет сквозной E2E-проверки. |
| `verified` | Реализовано + unit + integration/E2E + security-review пройдены. |

---

## 1. АУДИТ (Phase 0 — выполнен, read-only)

### 1.1 Что уже есть (переиспользуем, НЕ дублируем)

| Подсистема | Файл(ы) | Состояние | Реюз в Workbench |
|-----------|---------|-----------|------------------|
| Signed PayloadRegistry + Builder | `backend/src/payloads/registry.py`, `builder.py`, `config/payloads/*` (54 семейства) | Зрелый: Ed25519, fail-closed, дедуп, `requires_approval` для HIGH/DESTRUCTIVE | Intruder/Scanner payload sets, mutation pipeline |
| Signed PromptRegistry (агенты) | `backend/src/llm_orchestrator/prompt_registry.py`, `config/prompts/*` | Зрелый: strict JSON schema, fixer retry | AI-ассистенты Repeater/Intruder/Scanner |
| Playbooks subsystem (uncommitted) | `backend/src/playbooks/{schema,registry,planner,executor,actions,oracles,cleanup,evidence,lifecycle}.py`, `config/playbooks/**` (12 сценариев) | Работает: signed fail-closed, ScenarioExecutor, 6 oracles, cleanup | Scanner checks, declarative check DSL основа |
| EAP | `backend/src/policy/engagement_authorization.py` | Зрелый: signed, action classes, авто-approval в scope, audit | EAP-гейт всех активных Workbench-операций |
| PreflightChecker (+EAP) | `backend/src/policy/preflight.py` | Зрелый: scope→ownership→policy→approval(+EAP) | Gate перед каждым HTTP/tool/scan job |
| ScopeEngine | `backend/src/policy/scope.py` | Зрелый: default-deny, deny>allow, suffix-match, БЕЗ DNS | Scope include/exclude, per-request scope check |
| OwnershipVerifier | `backend/src/policy/ownership.py` | Есть (DNS_TXT proof) | Ownership verification таргета |
| AuditLogger | `backend/src/policy/audit.py` | Hash-chain, immutable | Audit всех mutations |
| Sandbox exec | `backend/src/sandbox/{adapter_base,templating,manifest,k8s_adapter}.py`, `recon/sandbox_tool_runner.py` | argv-only, resource limits, NetworkPolicy | Запуск tool-джобов (nmap/nuclei/ffuf/…) |
| Signing infra | `backend/src/sandbox/signing.py` | KeyManager, sign/verify_blob | Подпись EAP, extension-манифестов, catalogs |
| Nuclei adapter (uncommitted) | `backend/src/recon/vulnerability_analysis/active_scan/nuclei_va_adapter.py` | argv-allowlist + `-t` для `argus-*` templates | Scanner integration, НЕ второй pipeline |
| OAST plane | `backend/src/oast/{provisioner,correlator,canary,integration,...}.py` | tenant-isolated, dedup, DNS/HTTP | Collaborator/OAST паритет |
| Playwright adapter (uncommitted) | `backend/src/sandbox/playwright_adapter.py` | `login_flow(storage_state=)` reusable session, `export_auth_context` | Embedded browser, DOM instrumentation |
| Multi-principal auth (uncommitted) | `backend/src/auth/{session_store,redaction}.py`, `orchestration/auth_config.py` | PrincipalSession, split-plane secrets, SessionStore | Auth Analyzer, per-principal sessions |
| FindingDTO + ScenarioContextDTO (uncommitted) | `backend/src/pipeline/contracts/finding_dto.py`, `reports/finding_bridge.py` | Расширен baseline/mutated/diff/oracle/approval | Evidence-first reporting |
| MCP server | `backend/src/mcp/**`, `config/mcp/server.yaml` | FastMCP, tenant-scoped, audit, OpenAPI emitter → SDK | Аддитивные web_* tools |
| DB / RLS | `backend/src/db/models*.py`, `alembic/versions/*` (head=044) | String(36) UUID, GUC `app.current_tenant_id`, FORCE RLS | Новые tenant-scoped таблицы |

### 1.2 Ключевые инварианты платформы (подтверждены аудитом)

- UUID = `String(36)` (НЕ native pg UUID). PK `default=gen_uuid`.
- `tenant_id String(36) FK tenants.id ondelete=CASCADE nullable=False`.
- RLS: `ENABLE` + `FORCE` + policy `USING/WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)`; per-session `set_session_tenant()`.
- Alembic naming `NNN_slug.py`, `revision`/`down_revision` строки; новый файл моделей импортируется в `alembic/env.py`.
- Migrations оборачивают RLS в `if bind.dialect.name == "postgresql"` (SQLite smoke).
- Внешние команды — argv only, без shell.
- Секреты — split-plane: LLM видит `principal_id`/`secret_ref`; реальные значения — только на execution-слое.

### 1.3 Gap analysis (Burp → ARGUS)

Основной вывод: **ядро зрелое**. Отсутствует именно «web workbench execution-plane»:
интерсептирующий прокси, traffic store (raw+normalized), message editor, Repeater/Intruder/
Sequencer/Decoder/Comparer/Logger/Organizer инструменты, extension platform, и операторский UI.
Всё это надстраивается над существующими scope/preflight/EAP/payload/playbook/finding слоями.

---

## 2. CAPABILITY MATRIX (Burp → ARGUS)

Статусы отражают состояние на момент старта этой оркестрации.

### 2.1 Dashboard / Target / Proxy / Browser

| # | Capability (Burp) | ARGUS-реализация | Статус |
|---|-------------------|------------------|--------|
| 4.1 | Dashboard (tasks, live events, issues, kill switch, resource usage) | `admin-frontend` + SSE/WS из control-plane | `missing` |
| 4.2 | Target / Site map / Scope (hierarchy, include/exclude, import HAR/OpenAPI/Postman/GraphQL/WSDL) | `web_workbench/target` + `ScopeEngine` + `WebWorkbenchProject`/scope models | `partial` (scope-движок есть; site map/import — нет) |
| 4.3 | Intercepting Proxy (HTTP/1.1, HTTP/2, HTTPS MITM, WS, listeners, match/replace, CA mgmt) | `argus-web-proxy` service + `web_workbench/proxy` + `ProxyListener` model | `missing` |
| 4.4 | Embedded Browser (isolated context, login record/replay, DOM instrumentation) | `web_workbench/browser` + существующий Playwright adapter | `partial` (login_flow/storageState есть) |

### 2.2 Manual tools

| # | Capability | ARGUS | Статус |
|---|-----------|-------|--------|
| 4.5 | Message Editor / Inspector (raw/pretty/hex, structured, JWT/GraphQL) | `web_workbench/message_editor` (shared component, back+front) | `missing` |
| 4.6 | Repeater (tabs, history/revisions, HTTP1/2, WS replay, AI assist) | `web_workbench/repeater` + `RepeaterTab`/`MessageRevision` | `missing` |
| 4.7 | Intruder (Sniper/Battering ram/Pitchfork/Cluster bomb, processors, high-volume pool) | `web_workbench/intruder` + PayloadRegistry + separate worker pool | `missing` |
| 4.9 | Sequencer (token entropy, chi-square, serial correlation, charts, export) | `web_workbench/sequencer` | `missing` |
| 4.10 | Decoder / Transformer (URL/Base64/hex/JWT/gzip/hash chains) | `web_workbench/decoder` | `missing` |
| 4.11 | Comparer (byte/word/JSON/DOM diff) | `web_workbench/comparer` | `missing` |
| 4.12 | Logger / Search (unified traffic journal, filters, saved searches) | `web_workbench/logger` + `TrafficMessage` store | `missing` |
| 4.13 | Organizer (inbox, collections, tags, status workflow) | `web_workbench/organizer` + `OrganizerCollection`/`OrganizerItem` | `missing` |

### 2.3 Scanner / OAST / IAST / Engagement

| # | Capability | ARGUS | Статус |
|---|-----------|-------|--------|
| 4.8 | Scanner / Crawler / Live Audit (passive+active, insertion points, FP verifier, Nuclei→FindingDTO) | `web_workbench/scanner` + playbooks + nuclei_va_adapter (расширить, НЕ дублировать) | `partial` (playbooks/oracles/nuclei есть) |
| 4.14 | Collaborator / OAST | существующий `src/oast/*` (расширить SMTP, Collaborator-Everywhere policy) | `partial` |
| 4.15 | DOM Invader / Clickjacking / IAST | `web_workbench/browser` + `checks` (canary DOM XSS, postMessage, CSP, frameability) | `missing` |
| 4.16 | Project & engagement management (config, secrets, snapshots, presets, scheduling, CI/CD) | `web_workbench/projects` + `WebWorkbenchProject` + scan schedules (есть) | `partial` |

### 2.4 Extension platform + native BApp-модули

| # | Capability | ARGUS | Статус |
|---|-----------|-------|--------|
| 5 | Extension platform (signed manifest, permissions, hooks, isolation, MCP contributions) | `web_workbench/extensions` | `missing` |
| 5 | Declarative check DSL (BCheck-подобный, нативный) | расширение `playbooks/schema.py` + `web_workbench/checks` | `partial` (playbook schema — основа) |
| 6.1 | BurpSuite-For-Pentester методики → playbooks | `config/playbooks/**` + provenance | `partial` |
| 6.2 | ActiveScan++ | `web_workbench/checks/active_scan_plus` | `missing` |
| 6.3 | Auth Analyzer / Autorize | `web_workbench/checks/authorization_analyzer` + SessionStore | `partial` (SessionStore/principals есть) |
| 6.4 | NoSQLi scanner | `web_workbench/checks/nosqli` (pure passive analyzer ✅ WB-P7c) + PayloadRegistry family (active, live) | `partial` |
| 6.5 | WordPress scanner | `web_workbench/checks/wordpress` + CVE/KEV/EPSS correlation | `missing` |
| 6.6 | Nuclei integration (per-request, custom templates) | расширение `nuclei_va_adapter.py` | `partial` |
| 6.7 | Wordlist Extractor | `web_workbench/wordlists` + `WordlistCorpus` | `missing` |
| 6.8 | Pentest Mapper (flow↔checklist, WSTG/ASVS coverage) | `web_workbench/checklist` + WSTG registry (есть) | `partial` |
| 6.9 | Pentest-Tools.com connector | `web_workbench/integrations` | `missing` |
| 6.x | Param Miner / Turbo Intruder / JWT Editor / HTTP Request Smuggler / Hackvertor / Upload Scanner / Retire.js / GAP / Logger++ / Request Redactor | `web_workbench/{intruder,decoder,checks}` (поведенческий паритет) | `missing` |

### 2.5 Payload / Prompt / MCP / Data model

| # | Capability | ARGUS | Статус |
|---|-----------|-------|--------|
| 7 | Payload catalog (полное покрытие классов, mutation pipeline, sign/drift) | расширение `config/payloads/**` | `partial` (54 семейства) |
| 8 | Prompt registry (24 workbench-промпта, strict schema, injection fixtures) | расширение `config/prompts/**` | `partial` |
| 9 | MCP web_* tools/resources/prompts | расширение `src/mcp/**` | `missing` |
| 11 | Data model (24 модели) + versioned API | `web_workbench` models + `api/routers/web_workbench/*` | `missing` |

---

## 3. АРХИТЕКТУРНЫЕ РЕШЕНИЯ (ADR-сводка)

- **ADR-WB-1 (control-plane / execution-plane split).** FastAPI = control-plane (tenant,
  project, policy, state, jobs, API, audit). Отдельный сервис `argus-web-proxy` =
  execution-plane (HTTP interception, TLS, HTTP/2, WS, raw transport) с authenticated
  internal API и очередью событий (Redis). MITM НЕ встраивается напрямую в основной
  FastAPI-процесс, чтобы не смешивать доверенный control-plane и raw-трафик.
- **ADR-WB-2 (bodies в MinIO, метаданные в PG).** Большие/raw тела запросов-ответов —
  в MinIO (tenant-scoped path) с `TrafficBodyArtifact` (object ref, content hash, size,
  encoding, redaction status, retention). В PG — метаданные, индексы, связи.
- **ADR-WB-3 (raw preservation).** Хранятся одновременно exact/raw message и normalized
  parsed representation, HTTP version, header order, duplicate/pseudo headers, timing,
  TLS metadata, connection identity, redirect chain, WS frames, provenance, revision
  history. Raw НЕ нормализуется молча (нужно для Repeater/desync/forensic export).
- **ADR-WB-4 (единые gates).** Каждый активный шаг проходит `ScopeEngine` →
  `PreflightChecker` (+EAP) → sandbox. Никаких обходов PayloadRegistry/PromptRegistry.
- **ADR-WB-5 (единый Finding/Evidence).** Все находки → `FindingDTO` (+`ScenarioContextDTO`)
  через `finding_bridge`. Nuclei — единственный существующий adapter (никакого второго
  pipeline).
- **ADR-WB-6 (extension isolation).** Расширения исполняются в isolated process/container/
  WASM с resource quotas, egress policy, secret_ref permissions, подписанным манифестом.
- **ADR-WB-7 (EAP-first execution).** Ни одно state-changing/high-volume/destructive
  действие не запускается автоматически без предавторизованного класса в EAP и scope.
  `destructive_lab_only` — только с отдельным approval + snapshot/backup + cleanup.

---

## 4. МОДЕЛЬ ДАННЫХ (24 сущности, additive/backward-compatible)

Все модели tenant-scoped (`tenant_id` FK, RLS FORCE), с `created_at`/`updated_at`,
индексами `(tenant_id, ...)`, optimistic locking (`version`) там где конкурентные правки.

| Модель | Таблица | Ключевые поля | Фаза |
|--------|---------|---------------|------|
| WebWorkbenchProject | `wb_projects` | name, status, config(JSONB), secrets_ref, version | 1 |
| EngagementAuthorizationProfileRecord | `wb_eap` | project_id, engagement_id, signed_profile(JSONB), status, expires, signer_key_id | 1 |
| WbScopeRule | `wb_scope_rules` | project_id, kind, pattern, deny, ports, note | 1 |
| SessionPrincipal | `wb_session_principals` | project_id, principal_id, role, secret_ref, storage_state_ref | 6 |
| SessionMacro | `wb_session_macros` | project_id, name, steps(JSONB) | 6 |
| ProxyListener | `wb_proxy_listeners` | project_id, host, port, mode, ca_ref, upstream, status | 2 |
| TrafficMessage | `wb_traffic_messages` | project_id, source, http_version, method, url, status, timing, tls_meta, conn_id | 2 |
| TrafficBodyArtifact | `wb_traffic_bodies` | message_id, direction, s3_key, sha256, size, encoding, redaction_status, retention | 2 |
| MessageRevision | `wb_message_revisions` | message_id, revision, raw_ref, note | 3 |
| RepeaterTab | `wb_repeater_tabs` | project_id, group, name, current_message_id | 3 |
| IntruderAttack | `wb_intruder_attacks` | project_id, strategy, base_message_id, status, budget, config(JSONB) | 4 |
| IntruderPayloadPosition | `wb_intruder_positions` | attack_id, index, marker, payload_set_ref | 4 |
| ScannerTask | `wb_scanner_tasks` | project_id, kind(crawl/audit), status, config, checkpoint | 5 |
| ScannerIssueLink | `wb_scanner_issue_links` | task_id, finding_id, confidence | 5 |
| OrganizerCollection | `wb_organizer_collections` | project_id, name, kind | 3 |
| OrganizerItem | `wb_organizer_items` | collection_id, message_id, finding_id, status, tags, notes | 3 |
| OASTToken | `wb_oast_tokens` | project_id, token, kind, ttl, created_at | 5 |
| OASTInteraction | `wb_oast_interactions` | token_id, protocol, remote_addr, payload_ref, correlated_finding_id | 5 |
| ExtensionManifest | `wb_extension_manifests` | name, version, permissions, hooks, checksum, signature, sbom_ref | 8 |
| ExtensionInstallation | `wb_extension_installations` | manifest_id, project_id, status, config | 8 |
| WordlistCorpus | `wb_wordlist_corpora` | project_id, name, source_filters, entries_ref, stats | 7 |
| ChecklistDefinition | `wb_checklist_definitions` | name, version, items(JSONB), provenance | 10 |
| ChecklistExecution | `wb_checklist_executions` | project_id, definition_id, item_id, status, evidence_ref, finding_id | 10 |

---

## 5. ВЕРТИКАЛЬНЫЕ ЭТАПЫ (task IDs + deps)

| Task ID | Фаза | Зависимости | Deliverable |
|---------|------|-------------|-------------|
| WB-P0-AUDIT | 0 | — | Аудит + эта capability matrix (✅ done) |
| WB-P1-FOUNDATION | 1 | P0 | Domain models (project/EAP/scope), migration, RLS, contracts, service, API-заготовка |
| WB-P2-PROXY | 2 | P1 | `argus-web-proxy` service, traffic store, CA mgmt, proxy history API/UI |
| WB-P3-MANUAL | 3 | P2 | Message editor, Repeater, Decoder, Comparer, Organizer ✅ |
| WB-P4-INTRUDER | 4 | P3 | Intruder engines, wordlists, processors, scheduler, result analysis |
| WB-P5-SCANNER | 5 | P2 | Crawler/scanner/live audit, passive checks, Nuclei bridge, OAST↔FindingDTO |
| WB-P6-AUTH | 6 | P3 | Multi-principal SessionStore (persist), Auth Analyzer, macros, DOM instrumentation |
| WB-P7-NATIVE | 7 | P5 | ActiveScan++, NoSQLi, WordPress, Param Miner, JWT, dep-scan, smuggling/desync |
| WB-P8-EXT | 8 | P5 | Extension SDK, declarative check DSL, permissions, isolation, admin governance |
| WB-P9-AI-MCP | 9 | P5 | AI prompt registry (24), MCP tools/resources/prompts, generated SDK |
| WB-P10-MAP | 10 | P5 | Pentest Mapper / checklists / WSTG coverage, reports, imports/exports, connector |
| WB-P11-QA | 11 | P1–P10 | E2E, security review, load/resilience, docs, финальный аудит |

Граф:
```
P0 → P1 → P2 → P3 → P4
            └→ P5 → {P6, P7, P8, P9, P10} → P11
```

---

## 6. ACCEPTANCE CRITERIA (per phase, кратко)

- **P1:** модели создаются миграцией (upgrade+downgrade), RLS FORCE на всех новых таблицах,
  cross-tenant integration test (postgres) отказывает; contracts валидируются Pydantic
  (`extra="forbid"`); service переиспользует `ScopeEngine`+`EngagementAuthorizationService`;
  back-compat (старые API/scan-конфиги не ломаются); `ruff`/`black`/`mypy` чисто; import-cycle
  test зелёный; alembic upgrade smoke (sqlite) проходит.
- **P2:** прокси перехватывает HTTP/1.1+HTTPS, пишет raw+normalized в store, tenant CA
  генерируется/шифруется/ротируется; каждый forwarded request проходит scope+preflight;
  proxy→history виден в UI; benchmark задокументирован; нет unbounded in-memory bodies.
- **P3–P10:** см. соответствующие разделы ТЗ (§4.5–4.16, §5–§10) — каждая capability
  переходит `missing→implemented→verified` с тестами и security-review.
- **P11:** Definition of Done (§14 ТЗ) выполнен.

---

## 7. MIGRATION STRATEGY

- Одна миграция на фазу-группу таблиц, `NNN_wb_<slice>.py`, `down_revision` = текущий head.
- Каждая: `op.create_table` (mirror ORM) → индексы `(tenant_id, ...)` → RLS-блок под
  `if is_postgres` (ENABLE+FORCE+policy) → SQLite создаёт plain indexes для smoke.
- `downgrade()` — обратный порядок (DROP POLICY → NO FORCE → DISABLE RLS → DROP INDEX → DROP TABLE).
- Новый файл моделей (`models_web_workbench.py`) импортируется в `alembic/env.py`.
- Никаких изменений старых required-полей; только additive Optional.

## 8. TEST MATRIX (ссылка на §12 ТЗ)

Unit (parsers, scope, redirect scope, payload processing, decoder, comparer, sequencer stats,
message normalization, raw preservation, manifests, prompt schemas, checklist, finding norm),
Integration (proxy→history→repeater→intruder→evidence→finding; browser→auth analyzer;
nuclei→issue; payload→builder→preflight→exec; OAST→interaction→finding; checklist→WSTG;
extension isolation; MCP→service→audit), Security (cross-tenant, scope bypass, redirect OOS,
DNS rebinding, SSRF metadata, secret leakage, malicious manifest, tampered catalogs, cmd
injection, path traversal, stored XSS, prompt injection, CA exposure, EAP bypass, kill switch,
arbitrary shell reject), E2E (local target only), Perf/resilience.

## 9. SECURITY INVARIANTS (наследуются из pipeline-плана + новые)

- SI-1..SI-7 из `2026-07-22-argus-pipeline-playbooks.md` (approval/EAP, scope-SSRF,
  split-plane secrets, argv-only, no registry bypass, no prompt injection, back-compat).
- **SI-WB-1:** scope проверяется при create project / save target / перед каждым HTTP/WS
  запросом / перед redirect / перед OAST registration / перед scanner/intruder/tool job /
  после DNS resolution (rebinding) / перед каждым шагом playbook.
- **SI-WB-2:** CA-приватные ключи per-tenant, шифрованное хранение, ротация, revocation;
  никогда не логируются и не отдаются в открытом виде.
- **SI-WB-3:** kill switch мгновенно останавливает все активные джобы engagement.
- **SI-WB-4:** нет секретов в metric labels / cache keys / logs / prompts / evidence.
- **SI-WB-5:** `destructive_lab_only` — только явно помеченная lab-цель + отдельный
  approval/EAP + snapshot confirmation + обязательный cleanup; никогда не авто.

---

## 10. ТЕКУЩИЙ СТАТУС (обновляется после каждой фазы)

- ✅ **WB-P0-AUDIT** — completed.
- ✅ **WB-P1-FOUNDATION** — implemented + unit-verified (эта сессия). Доставлено:
  - `backend/src/db/models_web_workbench.py` — `WebWorkbenchProject`, `WbScopeRule`,
    `WebWorkbenchEapRecord` (tenant-scoped, индексы, optimistic-lock `version`).
  - `backend/alembic/versions/045_wb_foundation.py` — миграция с RLS (ENABLE+FORCE+policy,
    Postgres-only) и SQLite-smoke fallback; upgrade+downgrade; head=045, single head.
  - `backend/alembic/env.py` — регистрация нового модуля моделей.
  - `backend/src/web_workbench/{__init__,contracts,projects}` — strict Pydantic-контракты
    (`extra="forbid"`, default-deny scope, optimistic lock, secrets только по `secrets_ref`),
    `ProjectScopeService` (делегирует shared `ScopeEngine`), `evaluate_eap` (fail-closed через
    `EngagementAuthorizationService`).
  - `backend/tests/unit/web_workbench/test_project_contracts.py` — 11 тестов (контракты,
    scope allow/deny/default-deny, EAP invalid/unsigned/expired/verified).
  - **Проверки (эта сессия):** `ruff` ✅, `black --check` ✅, `mypy src/web_workbench` ✅
    (no issues, 5 files), `pytest tests/unit/web_workbench` ✅ (11 passed),
    `alembic heads` ✅ (045 single), `pytest tests/integration/migrations/test_alembic_smoke.py`
    ✅ (4 passed, 4 skipped=postgres).
  - **Не покрыто (следующий этап):** MCP tools для проектов (WB-P9), UI (Frontend, не менять — §10).
- ✅ WB-P1b — **DONE** (эта сессия). Async persistence-repository + versioned REST API + RLS
  integration test:
  - `backend/src/web_workbench/projects/repository.py` — async CRUD, optimistic lock по `version`,
    маппинг ORM↔DTO (scope rules, EAP), персист EAP через `evaluate_eap` (fail-closed: только
    `verified`), закрытая таксономия ошибок (`ProjectNotFound/NameConflict/OptimisticLock/EapRejected`).
  - `backend/src/api/routers/web_workbench/projects.py` + `__init__.py` — `POST/GET/PATCH
    /api/v1/wb/projects`, `POST /api/v1/wb/projects/{id}/eap`, paginated list; tenant-scoped session
    (`set_session_tenant` → RLS) + explicit `tenant_id` filter (defence-in-depth); ошибки без утечки
    stack trace. Смонтирован в `backend/main.py`.
  - `backend/src/core/config.py` (+`WB_EAP_KEYS_DIR`, default `backend/config/engagement/_keys`,
    fail-closed при отсутствии ключей).
  - `backend/src/web_workbench/contracts/project.py` (+`WorkbenchProjectListResponse`).
  - `docs/api-contracts.md` (§4a — контракт WB projects/EAP).
  - `backend/tests/unit/web_workbench/test_repository_mapping.py` — 6 тестов (round-trip маппинга).
  - `backend/tests/integration/web_workbench/test_projects_rls.py` (requires_postgres) — cross-tenant
    RLS изоляция (raw `SELECT count(*)` доказывает RLS, не только DAO-фильтр), optimistic-lock conflict,
    EAP fail-closed без ключей.
  - `backend/tests/test_argus003_api_contract.py` (+3 required OpenAPI paths).
  - **Проверки (эта сессия):** `ruff` ✅, `black` ✅, `mypy src/web_workbench src/api/routers/web_workbench`
    ✅ (8 files), `pytest tests/unit/web_workbench` ✅ (17 passed), контракт-тест
    `test_openapi_has_required_paths`/`test_openapi_validation_missing_paths_fails` ✅ (2 passed —
    live OpenAPI содержит новые пути), `test_no_cyclic_imports` ✅ (11 passed), route-mount smoke ✅.
  - **Postgres-gated (запуск при live DB):** `tests/integration/web_workbench/test_projects_rls.py`
    (collect OK, 3 deselected без `DATABASE_URL=postgresql`).
- ✅ WB-P2a-1 — **DONE** (эта сессия). Proxy data-plane core (pure, offline-tested):
  - `backend/src/web_workbench/proxy/transport.py` — HTTP/1.x normalization с byte-exact raw
    round-trip головы (ADR-WB-3), сохранение порядка/дубликатов/регистра заголовков,
    `to_target_spec()` → shared `ScopeEngine`; `plan_body` — bounded bodies (sha256+size, inline/
    spill/truncated, «no unbounded in-memory»).
  - `backend/src/web_workbench/proxy/ca_manager.py` — per-tenant CA (RSA-2048), constrained
    (`BasicConstraints ca=True,path_len=0`, `keyCertSign`), leaf issuance (SAN DNS/IP, EKU serverAuth,
    short-lived), private key НИКОГДА не логируется (redacted repr, guarded `export_private_key_pem`),
    load/round-trip.
  - `backend/src/web_workbench/proxy/intercept_rules.py` — чистый first-match-wins engine
    (method/host-suffix/path-prefix/content-type), ergonomics-only (НЕ security control).
  - `backend/src/web_workbench/proxy/forward_gate.py` — **обязательный** fail-closed gate
    (SI-WB-1): scope через shared `ScopeEngine` (default-deny) + pluggable `preflight_hook` для
    полного `PreflightChecker` (WB-P2b); closed-taxonomy reasons.
  - `backend/tests/unit/web_workbench/proxy/*` — 37 тестов (transport round-trip/body caps,
    CA sign-verify/SAN/EKU/redaction, intercept first-match, forward-gate scope/preflight).
  - **Проверки (эта сессия):** `ruff` ✅, `black` ✅, `mypy src/web_workbench/proxy` ✅ (5 files),
    `pytest tests/unit/web_workbench` ✅ (54 passed: 17 foundation + 37 proxy).
  - **Не покрыто (следующие срезы):** persistence/API/storage (WB-P2a-2), live mitm daemon +
    Docker + juice-shop E2E + full PreflightChecker (WB-P2b).
- ✅ WB-P2a-2 — **DONE** (эта сессия). Proxy persistence + storage + API:
  - `backend/src/db/models_web_workbench.py` (+`WbProxyListener`,`WbTrafficMessage`,
    `WbTrafficBodyArtifact`,`WbMessageRevision`); миграция `046_wb_proxy.py` (RLS+FORCE, sqlite fallback,
    up/down round-trip зелёный).
  - `backend/src/web_workbench/proxy/body_store.py` — `BodyObjectStore` Protocol + `InMemoryBodyObjectStore`
    (тест) + `S3BodyObjectStore` (поверх `src.storage.s3`, content-addressed key, тело не логируется).
  - `backend/src/web_workbench/proxy/repository.py` — listener CRUD (optimistic lock), traffic
    `persist_message` (bodies через `plan_body`: inline/spill/truncated), `list_history` paginated,
    `get_message`; RLS + explicit tenant filter; закрытая таксономия ошибок.
  - `backend/src/web_workbench/contracts/proxy.py` — `ProxyListener*`, `TrafficMessageDTO`, `BodyRef`,
    `CaInfo` (только public), `TrafficListResponse`; reuse `InterceptRuleSet`.
  - `backend/src/api/routers/web_workbench/proxy.py` (+mount) — 6 endpoints (listeners CRUD + history + message).
  - `docs/api-contracts.md` §4b; `test_argus003_api_contract.py` (+4 proxy paths).
  - `tests/unit/web_workbench/proxy/{test_body_store,test_proxy_repository_mapping}.py` (10 тестов);
    `tests/integration/web_workbench/test_proxy_rls.py` (requires_postgres — cross-tenant isolation
    через raw count, listener optimistic-lock, inline body round-trip).
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (18 files), `pytest tests/unit/web_workbench` ✅ (64 passed),
    contract required-paths ✅ (7 WB путей в live OpenAPI), alembic smoke ✅ (up/down 046), no-cyclic ✅.
  - **Решение (честно):** CA issuance/rotation НЕ здесь — вынесено в WB-P2b-1 (ниже).

### WB-P2b-1 — CA lifecycle (sealing + issue/rotate + API) — ✅ DONE (эта сессия)
- **Files:**
  - `backend/src/web_workbench/proxy/ca_lifecycle.py` — `SecretSealer` Protocol + `FernetSecretSealer`
    (KEK из `settings.wb_ca_sealing_key`/`WB_CA_SEALING_KEY`), `build_sealer_from_settings()` (fail-closed
    → `None` если KEK не задан), `issue_ca()` → `SealedCa`(public cert + fingerprint + sealed priv key +
    `secrets_ref`), `load_ca()` (unseal + rebuild `CertificateAuthority` для подписи листов).
  - `src/core/config.py` — `wb_ca_sealing_key` (env-only, никогда literal).
  - `src/db/models_web_workbench.py` — колонка `WbProxyListener.ca_sealed_key` (LargeBinary, ciphertext);
    `alembic/versions/047_wb_ca_sealed_key.py` (additive, RLS без изменений).
  - `src/web_workbench/proxy/repository.py` — `set_listener_ca()` (optimistic-lock, пишет только
    public cert + fingerprint + sealed key + secrets_ref).
  - `src/web_workbench/contracts/proxy.py` — `CaIssueRequest{expected_version, common_name?}`.
  - `src/api/routers/web_workbench/proxy.py` — `POST /wb/proxy/listeners/{id}/ca` (issue/rotate,
    fail-closed 503 без KEK, 409 version, 404; ответ — `ProxyListenerDTO` только с public CA).
  - `docs/api-contracts.md` §4b; `test_argus003_api_contract.py` (+`.../ca` path).
  - `tests/unit/web_workbench/proxy/test_ca_lifecycle.py` (6 тестов);
    `tests/integration/web_workbench/test_proxy_rls.py` (+issue→persist sealed→reload from DB→sign leaf).
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (3 files), unit ✅ (6 passed), alembic smoke ✅ (047 в цепочке),
    live OpenAPI содержит `.../ca` ✅.
  - **Инвариант:** приватный ключ CA в БД только как Fernet-ciphertext (`ca_sealed_key`); plaintext —
    только в памяти через `load_ca`; никогда в логах/API. Без KEK — 503 (no plaintext fallback).

### WB-P3a — Decoder + Comparer (pure, offline) — ✅ DONE (эта сессия)
- **Files:**
  - `backend/src/web_workbench/decoder/{__init__,engine}.py` — chainable transform engine (bytes→bytes):
    url/base64/base64url/hex/html (en|de)code, gzip (compress|decompress, inflate ≤16 MiB anti-bomb),
    `jwt_decode` (header+payload, БЕЗ verify), `hash` (md5/sha1/sha256/384/512), `hmac` (keyed).
    **Инвариант:** keyed-ops только через инъектируемый `SecretResolver`+`secret_ref`; inline
    `key`/`secret` отклоняются; без resolver → fail-closed `DecoderError`.
  - `backend/src/web_workbench/comparer/{__init__,engine}.py` — детерминированный diff:
    byte/word/line (opcode), json (order-insensitive canonicalise), dom (нормализованный HTML-токен-стрим,
    игнор порядка атрибутов/пробелов); `result_to_dict` — JSON-safe вывод.
  - `backend/src/web_workbench/contracts/tools.py` — `DecoderRequest/Response`, `ComparerRequest/Response`
    (base64 транспорт, size-cap, steps ≤32).
  - `backend/src/api/routers/web_workbench/tools.py` (+mount) — `POST /wb/tools/{decoder,comparer}`
    (stateless, auth-required, keyed-ops fail-closed 400 — секреты не пересекают API).
  - `docs/api-contracts.md` §4c; `test_argus003_api_contract.py` (+2 tool paths).
  - `tests/unit/web_workbench/{decoder,comparer}/*` — 30 тестов (round-trips, jwt, hmac fail-closed/inline
    reject, gzip-bomb guard, json order-insensitive, dom attr-order/whitespace).
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (6 files), unit ✅ (30 passed), live OpenAPI содержит tool paths ✅.

### WB-P3b-1 — Message editor + Repeater scope-gate engine (pure) — ✅ DONE (эта сессия)
- **Files:**
  - `backend/src/web_workbench/message_editor/{__init__,engine}.py` — `RawHttpMessage` (split head/body,
    byte-exact), `with_body` (сохраняет head-байты точно, БЕЗ auto-Content-Length), `pretty_request/response`
    (нормализованный вид, JSON-body indent, дубли/порядок заголовков сохранены), `hex_dump`.
    **Инвариант:** pretty/hex — read-only проекции; транспорт всегда из raw-байт (никакой ре-сериализации).
  - `backend/src/web_workbench/repeater/{__init__,engine}.py` — `RepeaterService.replay(raw, sender)`:
    парс→`ForwardGate`(scope+optional preflight)→**если blocked, sender НЕ вызывается**→иначе inject
    `HttpSender.send`. `HttpSender` — Protocol (реальный httpx-sender = P3b-2, сеть infra-gated).
  - `backend/src/web_workbench/contracts/tools.py` — `MessageFormatRequest/Response`, `HeaderDTO`.
  - `backend/src/api/routers/web_workbench/tools.py` — `POST /wb/tools/message-format` (stateless, auth;
    hex всегда, pretty/parsed=null при malformed head).
  - `docs/api-contracts.md` §4c; `test_argus003_api_contract.py` (+message-format path).
  - `tests/unit/web_workbench/{message_editor,repeater}/*` — 16 тестов (byte-exact override, dup-headers,
    pretty-json, hex; **replay: sender.calls==0 при out-of-scope/preflight-deny/unresolvable/malformed**).
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (6 files), unit ✅ (16 passed; весь web_workbench — 116), live OpenAPI ✅.

### WB-P3c — Organizer (collections + items, persist) — ✅ DONE (эта сессия)
- **Files:**
  - `backend/src/db/models_web_workbench.py` — `WbOrganizerCollection` (unique name/project, optimistic `version`),
    `WbOrganizerItem` (raw_request/raw_response byte-exact `LargeBinary`, `tags` JSONB, `source_message_id`→SET NULL,
    индексы collection/host).
  - `backend/alembic/versions/048_wb_organizer.py` — RLS ENABLE+FORCE+`tenant_isolation` (Postgres) + SQLite-smoke
    fallback; upgrade/downgrade round-trip; head=048.
  - `backend/src/web_workbench/organizer/{__init__,repository.py}` — async CRUD + optimistic lock + поиск
    (`collection_id`/`host`/`tag`=JSONB containment/`q`=title ilike); ORM↔DTO mapping; `purge_project_organizer`.
    **Defence-in-depth:** RLS-session + explicit `tenant_id` filter. Raw-байты не логируются.
  - `backend/src/web_workbench/contracts/organizer.py` — strict (`extra="forbid"`) контракты; raw как base64,
    size-capped (~1 MiB); `tags`≤32 дедуп/трим; raw возвращается ТОЛЬКО в single-item GET.
  - `backend/src/api/routers/web_workbench/organizer.py` + mount — 10 endpoints (`/wb/*/organizer/*`),
    ошибки 404/409/400 без утечки; `docs/api-contracts.md` §4d; `test_argus003_api_contract.py` (+5 paths).
  - `tests/unit/web_workbench/organizer/test_organizer_mapping.py` — 5 тестов (mapping, raw include/omit, tags-нормализация);
    `tests/integration/web_workbench/test_organizer_rls.py` — 3 теста (cross-tenant RLS raw `count(*)`, optimistic lock,
    поиск tag/host/title), `requires_postgres`.
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (4 files), unit ✅ (весь web_workbench — **121 passed**),
    alembic smoke ✅, live OpenAPI ✅ (5 paths). Postgres RLS integration — **verify на live Postgres**.

### WB-P3b-2 — Repeater persistence + live sender — ✅ DONE (эта сессия, кроме live-send E2E)
- **Files:**
  - `models_web_workbench.py` — `WbRepeaterTab` (raw_request byte-exact, scheme/host/port, optimistic `version`),
    `WbRepeaterExchange` (raw_request, forward_outcome, block_reason, status_code, raw_response bounded, `truncated`,
    duration_ms).
  - `alembic/versions/049_wb_repeater.py` — RLS ENABLE+FORCE+policy (Postgres) + SQLite-smoke fallback; head=049.
  - `web_workbench/repeater/repository.py` — tabs CRUD (RLS + optimistic lock) + `record_exchange`/`list_exchanges`
    (history); ORM↔DTO mapping (raw только в single-item).
  - `web_workbench/repeater/sender.py` — `HttpxSender`: bounded streaming read (5 MiB, `truncated`), hop-by-hop strip
    (Host/Content-Length/TE/Connection), `follow_redirects=False`, injectable `httpx.Client` (MockTransport-тестируем).
  - `web_workbench/contracts/repeater.py` — strict контракты (raw base64 ≤~1 MiB).
  - `api/routers/web_workbench/repeater.py` + mount — 8 endpoints `/wb/*/repeater/*`; **kill-switch** (replay только при
    `status=active` → иначе 409); replay ТОЛЬКО через `RepeaterService`; malformed→400, upstream-fail→502.
  - `docs/api-contracts.md` §4e; `test_argus003_api_contract.py` (+5 paths).
  - `tests/unit/web_workbench/repeater/{test_sender,test_repeater_mapping}.py` — 11 тестов (MockTransport egress,
    framing-strip, bounded/truncated, mapping, target-derivation); `tests/integration/web_workbench/test_repeater_rls.py`
    — 3 теста (cross-tenant raw `count(*)`, optimistic lock, **out-of-scope replay → blocked, `sender.calls==0`**),
    `requires_postgres`.
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (6 files), unit ✅ (весь web_workbench — **132 passed**), alembic smoke ✅,
    live OpenAPI ✅ (5 paths). Postgres RLS integration + live-send E2E — **infra-gated verify**.

### WB-P4a — Intruder attack core (pure, offline) — ✅ DONE (эта сессия)
- **Files:** `web_workbench/intruder/`:
  - `positions.py` — `parse_template`/`ParsedTemplate` ({{…}}-маркеры, base-value round-trip byte-exact, `MAX_POSITIONS`).
  - `strategies.py` — `Strategy`(Sniper/Battering-ram/Pitchfork/Cluster-bomb) + `iter_assignments`/`total_requests`,
    budget-cap `MAX_TOTAL_REQUESTS`; process применяется к payload, base-value untouched.
  - `processors.py` — `Processor`+`apply_processors`: prefix/suffix/encode(url/base64/hex/html)/hash(md5/sha1/sha256)/
    regex_replace (bytes-chain, детерминизм).
  - `analysis.py` — `grep_match`(literal/regex)/`grep_extract`(capture group)/`dedup`(first-per-key + dropped).
  - `engine.py` — `generate_requests` (positions+strategy+processors → byte-exact raw) + `planned_total`.
  - **Инварианты:** payload sets — вход, источник ТОЛЬКО `PayloadRegistry`/`PayloadBuilder` (SI-5); нет I/O/сети/БД.
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (6 files), unit — **40 тестов** (4 стратегии, processors, grep, dedup,
    byte-exact render); весь `tests/unit/web_workbench` — **172 passed**.

### WB-P5a — Passive HTTP audit analyzer (pure, offline) — ✅ DONE (эта сессия)
- **Files:** `web_workbench/passive/{__init__,analyzer.py}`:
  - `analyze()` над захваченной парой `NormalizedRequest`/`NormalizedResponse` (proxy/repeater history), **без egress**;
    native passive-scanner, НЕ дублирует active Nuclei pipeline (SI: extend, not duplicate — проверено, что
    `va_http_audit.py` — лишь audit-строки, OAST-коррелятор в `src/oast/correlator.py` не трогается → интеграция в P5b).
  - Проверки: `check_security_headers` (HSTS на https / nosniff / CSP / clickjacking с учётом CSP frame-ancestors),
    `check_cookies` (Set-Cookie без Secure(https)/HttpOnly/SameSite — evidence = имя cookie, НЕ значение),
    `check_info_disclosure` (Server/X-Powered-By/X-AspNet-Version с версией), `check_cors` (wildcard-origin+credentials),
    `check_reflected_input` (query/urlencoded-body param отражён в теле → passive XSS-кандидат, `SUSPECTED`).
  - `PassiveFinding` переиспользует таксономию платформы (`FindingCategory`/`ConfidenceLevel` из `finding_dto`) +
    coarse `PassiveSeverity` → чистый мост в `FindingDTO` (WB-P5b) без bespoke-маппинга; `analyze` дедуплицирует по
    `(code, location, evidence)`; noise-guards (`_MIN_REFLECT_LEN`, `_MAX_REFLECT_FINDINGS`).
  - **Инварианты ✅:** offline (нет I/O/сети/БД); passive-only (низкая уверенность, кандидаты, не доказательства);
    evidence secret-free (имена, не значения cookie/токенов).
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (2 files), unit — **13 тестов** (все проверки + позитив/негатив + dedup);
    весь `tests/unit/web_workbench` — **185 passed**.

### WB-P5b-1 — Scanner persistence models + passive→FindingDTO bridge (offline) — ✅ DONE (эта сессия)
- **Files:**
  - `src/db/models_web_workbench.py` (+`WbScannerTask` — kind(crawl/audit/passive)/status/config/checkpoint/
    requests_total/findings_total/version, optimistic-lock; `WbScannerIssueLink` — task↔finding association с
    unique `(tenant,task,finding)`, confidence, link-back на traffic message).
  - `backend/alembic/versions/050_wb_scanner.py` — миграция RLS (ENABLE+FORCE+policy, Postgres) + `_json_type`
    (JSONB/SQLite JSON) + sqlite-smoke fallback; upgrade+downgrade; head=**050** single.
  - `src/web_workbench/passive/finding_bridge.py` — **чистый** маппер `PassiveFinding`→`FindingDTO`:
    `passive_finding_to_dto`/`passive_findings_to_dtos`, стабильные таблицы code→CWE и severity→(CVSS v3.1 vector,
    score), evidence_tier (INFORMATIONAL для hygiene, SUSPECTED для reflected-input), status=NEW, remediation с
    контекстом; fail-closed на неизвестный code/severity.
  - **Инварианты ✅:** offline (нет I/O/сети/БД); passive-findings НЕ претендуют на эксплуатацию (tier ≤ SUSPECTED,
    status NEW → промоушен только через FP-verifier/человека в P5b-2); identity (tenant/scan/asset/tool_run) — вход,
    владелец контекста — orchestrator; НЕ дублирует finding-контракт (переиспользует пайплайновый `FindingDTO`).
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (4 files), unit — **20 тестов** (все 10 codes→valid DTO,
    severity→CVSS, category/confidence carry, remediation-контекст, explicit id, fail-closed, batch, analyze→dtos
    e2e); alembic `heads`=050 single; alembic smoke ✅ (4 passed, 4 postgres-skipped); весь `tests/unit/web_workbench`
    — **205 passed**.
- ⏳ WB-P2b-2, P4b, **P5b-2** (scanner-orchestrator/crawler/Nuclei-extend/OAST-bridge/repository-RLS/API — infra-gated),
  P6b..P11 — pending (§11 backlog).

### WB-P6a — Authorization analyzer (owner/attacker/anon diff → BAC/IDOR, pure) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/checks/{__init__,authorization_analyzer.py}`:
  - Тонкий **offline-адаптер** поверх существующего `playbooks.oracles.AuthzOracle` (IDOR/BOLA) — вердикт-логика
    (denied-status, JSON field-diff, volatile-suppression, byte-identical raw compare, «no bare 2xx»)
    **переиспользована, НЕ дублирована** (инвариант extend). Адаптирует захваченный workbench-трафик
    (`NormalizedRequest`/`NormalizedResponse`+bodies) в `HttpExchange` и добавляет классификацию.
  - `analyze_authorization(owner, attackers[…])` → `AuthorizationFinding` только для вердикта FINDING;
    классификация `AuthzClass`: `UNAUTH_ACCESS` (анонимный принципал, приоритет) / `IDOR` (в URL есть object-id —
    `detect_object_id`: numeric/uuid/long-hex) / `BFLA` (иначе). `evaluate_pair` отдаёт сырой `OracleResult`
    (NO_FINDING/INCONCLUSIVE), owner-не-2xx → INCONCLUSIVE (fail-closed).
  - **Инварианты ✅ (SI-3):** finding НЕ содержит raw-тел — только oracle reason, differing **field paths**
    (не значения), object-id (URL-токен, не секрет), метаданные; нет I/O/сети/БД; пустой список атакующих → fail-closed.
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (2 files), unit — **16 тестов** (IDOR/BFLA/unauth, denied→no-finding,
    different-data→no-finding, owner-не-2xx→inconclusive, sensitive-field match, multi-attacker, object-id detect,
    no-secret-leak); весь `tests/unit/web_workbench` — **221 passed**.

### WB-P7a — Client dependency scanner (Retire.js-подобный, pure) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/checks/client_dependency.py`:
  - **Behavioral-аналог** Retire.js (НЕ копия кода/БД): по захваченному JS-контенту и/или URL скрипта определяет
    библиотеку+версию по сигнатурам и флагует версии в known-vulnerable диапазонах. **Pure**, offline;
    НЕ дублирует server-side SCA (`dependency_check.py` — Stage3-gate) и JS-endpoint-extractor (`recon_js_analysis`).
  - `detect_libraries(content/uri)`→`DetectedLibrary`; `match_vulnerabilities`/`scan` (dedup по (lib,ver,CVEs));
    semver-сравнение с `at_or_above`/`below` семантикой диапазонов; мост `dependency_findings_to_dtos`→`FindingDTO`
    (category SUPPLY_CHAIN, severity→CVSS, per-vuln CWE 79/1321/1333, evidence_tier INFORMATIONAL, confidence LIKELY).
  - **Provenance ✅:** курированный датасет из **публичных NVD/CVE-advisory** (jquery/bootstrap/lodash/angularjs/
    moment/handlebars, каждая запись цитирует CVE); SI-3: finding без секретов (только lib/version/CVE/URL-evidence).
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (3 files), unit — **16 тестов** (detect uri/content, vuln/patched,
    range-boundaries, bootstrap-v4, lodash-high, dedup uri+content, bridge→DTO, moment boundaries, negative);
    весь `tests/unit/web_workbench` — **237 passed**.

### WB-P7b (jwt_editor) — JWT inspector/analyzer (pure) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/checks/{severity.py,jwt_editor.py}`:
  - `severity.py` — общий `CheckSeverity`(info/low/medium/high/critical) + `cvss_for` (единый источник severity→CVSS
    для native-checks, устраняет дублирование мапы).
  - `jwt_editor.py` — `decode_jwt`/`is_jwt` (header+payload, **без верификации подписи** — analysis only, дополняет
    decoder `jwt_decode` структурным анализом, extend); `analyze_jwt` → `JwtFinding`: `alg=none` (critical),
    empty-signature (high), embedded `jwk` (high), `jku`/`x5u` внешний ключ (medium), `kid`-injection (medium),
    no-`exp`/expired/excessive-lifetime, sensitive-claim (password/secret/ssn/… по имени ключа). Мост
    `jwt_findings_to_dtos`→`FindingDTO` (category JWT, per-code CWE 347/91/613/522, severity→CVSS).
  - **Инварианты ✅ (SI-3):** finding НЕ содержит значений claim — только имена (`payload.password`) и метаданные;
    pure, offline; decode fail-closed (`JwtError`); dedup по `(code, evidence)`.
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (5 files), unit — **16 тестов** (decode roundtrip, alg-none, empty-sig,
    jwk/jku/x5u, kid-injection, no-exp/expired/long-exp, valid-exp clean, sensitive-claim no-leak, invalid→fail-closed,
    bridge→DTO, multi-weakness); весь `tests/unit/web_workbench` — **253 passed**.

### WB-P7c (nosqli) — NoSQL-injection passive analyzer (pure) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/checks/nosqli.py`:
  - Пассивный анализ захваченной пары request/response (**без отправки**): (1) **operator-injection** —
    Mongo-операторы во входе клиента: bracket-форма `param[$ne]` в query/urlencoded-body, `$op`-токен в значении,
    `$`-ключи в JSON-body (рекурсивный обход); (2) **error-signature** — NoSQL-ошибка движка в теле ответа.
    Error-сигнатуры **переиспользуют** `DETECTION_SIGNATURES["nosql"]` из `recon/quick_fuzz/detection_sigs`
    (extend, не дублировать) + доп. Mongo/Couch маркеры. При со-возникновении operator+error → единый
    повышенный HIGH/LIKELY finding `nosqli-error-based`. Мост `nosql_findings_to_dtos`→`FindingDTO`
    (category NOSQLI, CWE-943, severity→CVSS через общий `severity.py`).
  - **Инварианты ✅ (SI-3):** finding содержит только имена операторов/параметров и совпавший error-маркер —
    НЕ значения; pure, offline; скан тела ответа ограничен (`_MAX_BODY_SCAN`=256 KiB, DoS-guard); dedup операторов
    по `(param,op)`; `$`-ключи, не входящие в whitelist операторов, игнорируются (no false-positive).
  - **Проверки:** ruff ✅, black ✅, mypy ✅, unit — **24 теста** (bracket/token/json/urlencoded operator, dedup,
    clean-request, non-operator `$`-key ignored, 5× error-signatures, bounded-scan, operator+error→error-based,
    operator-only/error-only→suspected, clean→empty, no-value-leak, bridge category/CWE/tier/CVSS, explicit-id,
    batch unique-id, e2e analyze→DTO); весь `tests/unit/web_workbench` — **277 passed** (+24).

### WB-P8a — Declarative check DSL (BCheck-подобный, pure) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/extensions/{__init__.py,check_dsl.py}`:
  - **Data-only схема** (fail-closed `ConfigDict(extra="forbid", frozen=True)`, как `playbooks/schema.py` —
    никакого Python/shell/eval/import): `DeclarativeCheck`(schema_version, check_id slug, name/author/version,
    category=`FindingCategory`, severity=`CheckSeverity`, confidence, cwe unique>0, scope passive/active,
    requires_oast, remediation) + `MatcherGroup`(op AND/OR) из `Matcher`(part∈8 частей × kind contains/regex/
    equals/status, negate, case_sensitive; regex/status валидируются на этапе загрузки) + `Extractor`(capped capture).
  - **Pure evaluator** `evaluate_check`/`evaluate_checks` над `NormalizedRequest`/`NormalizedResponse`(+body):
    part-аксессор, AND/OR-комбинация, negate, status exact/`Nxx`-class; scan-cap 512 KiB (DoS-guard), regex-len ≤512.
  - **OAST fail-closed:** `requires_oast`-чек не срабатывает без `oast_confirmed=True` от live-коррелятора (валидатор
    требует scope=active). Живой сети модуль не касается.
  - **Мост** `check_finding_to_dto`→`FindingDTO` (category/severity→CVSS через общий `severity.py`); `load_check`
    валидирует untrusted mapping → `DslError` (без pydantic/stack-trace наружу).
  - **Инварианты ✅:** data-not-code; fail-closed на unknown-key/bad-regex/wrong-part/oast-passive/dup-cwe/empty-group;
    extractor-capture обрезан (200 chars); pure, offline.
  - **Проверки:** ruff ✅, black ✅, mypy ✅, unit — **27 тестов** (10× schema-reject, regex/status/contains/equals
    case-sens, negate, AND/OR, request-side parts, OAST fail-closed+confirm, extractor capture+truncate, batch,
    bridge SUSPECTED/CONFIRMED tier+CVSS, bounded-scan); весь `tests/unit/web_workbench` — **304 passed** (+27).

### WB-P8b-1 — Extension manifest schema + signing CLI (pure, offline) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/extensions/manifest.py`, `backend/scripts/extension_sign.py`:
  - **`ExtensionManifest`** (fail-closed `extra="forbid"`+frozen): metadata + `permissions`(closed `ExtensionPermission`
    enum, unique) + embedded `checks: list[DeclarativeCheck]` (переиспользует P8a) + `sbom: list[SbomComponent]` +
    `ExtensionProvenance`. **Least-privilege инварианты (загрузка):** passive-check⇒`register_passive_check`,
    active-check⇒`register_active_check`, `requires_oast`⇒`use_oast`, `network_egress`⇒`provenance.source_url`
    (иначе hard-reject); unique check_id.
  - **`load_manifest`/`parse_manifest_bytes`** — fail-closed (`ManifestError`, без pydantic/YAML stack-trace наружу).
  - **`verify_and_load`** — Ed25519-verify через `SignaturesFile.verify_one` **ДО** парсинга (unsigned/tampered/
    unknown-key манифест не доходит до схемы), переиспользует `src/sandbox/signing.py` (не дублирует crypto).
  - **`scripts/extension_sign.py`** — generate-keys/sign/verify CLI, тонкий mirror `prompts_sign.py` над общим
    `signing.py` (bytes-on-disk SHA-256+Ed25519, structured JSON events, без stack-trace).
  - **Проверки:** ruff ✅, black ✅, mypy ✅ (2 files), unit — **21 тест** (schema valid/no-checks, non-mapping/
    unknown-key/bad-id/dup-perm/dup-check/bad-embedded-check reject; least-privilege passive/active/oast/egress ±;
    YAML roundtrip + invalid-YAML reject; **verify_and_load**: valid / tampered-reject / unknown-key-reject /
    unsigned-path-reject); весь `tests/unit/web_workbench` — **325 passed** (+21).

### WB-P7d — `wordpress` (pure passive CMS analyzer) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/checks/wordpress.py` (+ экспорт в `checks/__init__.py`):
  - `analyze(request, response, response_body)` → `list[WordpressFinding]`, дедуп по `code`. Пассивный (ничего не
    шлёт), offline, по образцу `nosqli`/`client_dependency`.
  - **Fingerprint** (`detect_fingerprint`): `X-Pingback`, `Link: rel=api.w.org`, `wordpress_*`/`wp-settings`
    Set-Cookie (только имя), `/wp-content|/wp-includes`, generator-meta.
  - **Version** (`detect_version`): generator-meta / feed `<generator>?v=` / `readme.html` (только на readme-пути).
  - **Misconfig:** REST user-enum (`/wp-json/wp/v2/users` 200 + `"slug"`), author-redirect enum (`?author=`→302→
    `/author/`), xmlrpc-enabled (405 / body-маркер), debug.log-exposed (200 → SECRET_LEAK), directory-listing
    (`Index of /wp-(content|includes)`).
  - **Мост → FindingDTO:** per-finding `category` (INFO/MISCONFIG/SECRET_LEAK), CWE (200/204/16/532/548), общий
    `severity.cvss_for`; CONFIRMED confidence → CONFIRMED tier (только response-proven), иначе SUSPECTED; status NEW.
  - **Security (SI-3):** evidence — только маркер/endpoint, НИКОГДА значения cookie/slug/username (проверено тестами).
  - **Проверки:** ruff ✅, black ✅, mypy ✅, unit — **21 тест** (5× fingerprint incl. cookie-no-leak/plain-site;
    3× version incl. readme-path-gated; rest/author enum secret-free; xmlrpc 405/body; debug.log 200 vs 404;
    dir-listing; clean-no-FP; dedup; 3× DTO tier/category/batch-ids); весь `tests/unit/web_workbench` — **428 passed** (+21).

### WB-P10a — HAR importer (pure, offline) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/imports/{__init__.py,har.py}`:
  - `import_har(raw)` → `list[ImportedExchange]` (url, `NormalizedRequest`, request_body, `NormalizedResponse|None`,
    response_body, started_at, truncated). Импортированный трафик строится на тех же transport-типах, что и live —
    напрямую питает proxy history / Repeater / passive-analyzer / DSL-evaluator.
  - **Fail-closed:** bad JSON / root-not-object / missing `log` / `entries`-not-array / entry без `request` /
    request без method|url → `HarImportError` (без stack-trace наружу).
  - **Bounded:** ≤20k entries, ≤5 MiB на тело (+`truncated` флаг) — DoS-guard для гигантских HAR.
  - **Security:** header-injection guard (drop CR/LF в name/value), HTTP/2 pseudo-headers (`:authority`) отброшены,
    Host синтезируется из URL при отсутствии; failed/aborted (`status=0`/нет) → `response=None` (не фабрикуем статус);
    base64-тела ответов декодируются.
  - **Проверки:** ruff ✅, black ✅, mypy ✅, unit — **18 тестов** (single/bytes/POST-body/base64/host-synth/multi-order;
    failed→no-response, missing-response; pseudo+injection headers dropped; body-truncation flag; entry-cap;
    6× fail-closed parse); весь `tests/unit/web_workbench` — **343 passed** (+18).

### WB-P10b — OpenAPI/Swagger importer (pure, offline) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/imports/{__init__.py,openapi.py}`:
  - `import_openapi(raw, *, base_url=None)` → `list[ImportedExchange]` — по одному синтетическому запросу на
    операцию (`response=None`, тот же `NormalizedRequest`/`ImportedExchange`-паттерн, что HAR → напрямую питает
    scope/scanner-targets/Repeater). Поддержка **OpenAPI 3.x и Swagger 2.0**, JSON и YAML (yaml.safe_load — суперсет).
  - **Резолв host:** `base_url` → OpenAPI3 `servers[0].url` → Swagger2 `schemes/host/basePath`; relative-server без
    `base_url` → fail-closed (target без authority не проходит scope-gate).
  - **Sample-значения** параметров/тела: `example` → `enum[0]` → тип-плейсхолдер (int→`1`, bool→`true`, str→`example`);
    path-params подставляются, required query-params добавляются, header-params прокидываются; JSON requestBody →
    `example`|`{}` + `Content-Type: application/json`. Значения нейтральные — не секреты.
  - **Fail-closed:** root-not-mapping / нет `openapi`|`swagger` / `paths`-not-mapping / битый JSON-YAML /
    невалидный синтетический запрос → `OpenApiImportError` (без stack-trace наружу).
  - **Bounded:** ≤5000 операций (DoS-guard); header-injection guard (drop CR/LF в name/value).
  - **Проверки:** ruff ✅, black ✅, mypy ✅, unit — **16 тестов** (basic op / YAML / multi-method / header-param /
    enum-path / body-example / body-default-`{}` / optional-query-omit / path-level-params / swagger2 host+basePath /
    base_url override / relative-reject; 4× fail-closed: invalid-doc / missing-version / missing-paths /
    non-operation-keys); весь `tests/unit/web_workbench` — **359 passed** (+16).

### WB-P10c — Postman Collection v2.1 importer (pure, offline) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/imports/{__init__.py,postman.py}`:
  - `import_postman(raw, *, variables=None)` → `list[ImportedExchange]` — request-only (`response=None`), тот же
    `ImportedExchange`/`NormalizedRequest`-паттерн, что HAR/OpenAPI (импорт = live-трафик для scope/Repeater/scanner/
    passive/DSL). Переиспользует хелперы `har._bounded/_ensure_host/_origin_form` (DRY, не форкает). JSON и YAML.
  - **Обход:** nested-folders depth-first (cap `_MAX_DEPTH=64`), `item.request` как объект или строка; ≤20k запросов.
  - **URL:** string-raw / url-object `raw` / компоненты (`protocol/host/path/query`); disabled-query отбрасывается;
    `{{var}}` резолвятся из collection-`variable` + url-`variable` (path-vars, включая `:id`-форму) + caller-override
    (`variables=`); bounded-passes (`_MAX_SUBST_PASSES=8`, анти-цикл).
  - **Headers/body:** disabled-headers пропускаются, CR/LF-guard; body-modes `raw` (+`Content-Type: application/json`
    при `language=json`), `urlencoded` (→ x-www-form-urlencoded), `formdata` (→ multipart с фикс-boundary);
    явный `Content-Type` из коллекции не перезаписывается.
  - **Fail-closed:** bad JSON/YAML / root-not-mapping / нет `info` / `item`-not-array / bad|unsupported method /
    пустой url / **неразрешённая `{{var}}`** / url без host-authority → `PostmanImportError` (без stack-trace).
  - **Проверки:** ruff ✅, black ✅, mypy ✅, unit — **20 тестов** (string/object-raw/object-components url; YAML;
    collection-var + override + `:id` path-var; headers + disabled + injection-drop; raw-json/urlencoded/formdata body;
    explicit-CT-preserved; nested-folders; 6× fail-closed); весь `tests/unit/web_workbench` — **379 passed** (+20).

### WB-P10d — GraphQL introspection importer (pure, offline) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/imports/{__init__.py,graphql.py}`:
  - `import_graphql_introspection(raw, *, endpoint_url)` → `list[ImportedExchange]` — по одному синтетическому HTTP
    `POST` на каждое корневое поле `Query`/`Mutation` (`response=None`, body = `{"query": "..."}`). Тот же
    `ImportedExchange`/`NormalizedRequest`-паттерн, переиспользует `har._ensure_host/_origin_form` (DRY). JSON и YAML;
    принимает как `{"data":{"__schema":…}}`, так и top-level `__schema`.
  - **Selection-set:** глубина-ограниченный (`_MAX_DEPTH=4`) обход композитных типов (OBJECT/INTERFACE), выбор
    leaf-полей (SCALAR/ENUM) без required-args; анти-цикл через `visited`-set; fallback `__typename`, если leaf нет;
    fan-out cap `_MAX_FIELDS_PER_LEVEL=50`.
  - **Args:** эмитятся только required-аргументы; scalar/enum-литералы (Int→`1`, Float→`1.0`, Boolean→`true`,
    ID→`"1"`, String/custom→`"example"`, ENUM→первое значение, без кавычек); required non-scalar (input-object) arg →
    операция пропускается (валидный запрос > неполный); NON_NULL/LIST-обёртки разворачиваются (bounded unwrap).
  - **Fail-closed:** пустой/без-host `endpoint_url`, bad JSON/YAML, root-not-mapping, нет `__schema`, `types`-not-array,
    нет импортируемых корневых полей → `GraphQLImportError` (без stack-trace). Bounded ≤2000 операций.
  - **Проверки:** ruff ✅, black ✅, mypy ✅, unit — **16 тестов** (query+mutation basic; scalar-root-no-selection;
    cyclic-guard; enum-arg-unquoted; Int/Float/Bool литералы; optional-args-omit; non-scalar-arg-skip;
    __typename-fallback; top-level-`__schema`; host-only endpoint; 6× fail-closed); весь `tests/unit/web_workbench`
    — **395 passed** (+16).

### WB-P10e — WSDL 1.1 importer (pure, offline) — ✅ DONE (эта сессия)
- **Files:** `src/web_workbench/imports/{__init__.py,wsdl.py}`:
  - `import_wsdl(raw)` → `list[ImportedExchange]` — по одному синтетическому HTTP `POST` на каждую SOAP-binding-операцию
    с резолвимым service-address; body = SOAP-envelope (Body → operation-элемент в `targetNamespace` + placeholder-parts).
    Тот же `ImportedExchange`/`NormalizedRequest`-паттерн, переиспользует `har._ensure_host/_origin_form` (DRY).
  - **SOAP 1.1 vs 1.2** определяется по namespace биндинга: разные envelope-ns, `Content-Type`
    (`text/xml`+`SOAPAction:"…"` vs `application/soap+xml; …; action="…"`).
  - **Parts:** RPC-style (`type=`) → `<part>sample</part>` (сэмпл по XSD-типу: numeric→`1`, boolean→`true`,
    date→ISO, иначе `example`); document-style (`element=`) → пустой `<Element/>`. Namespace-agnostic парсинг (local-name).
  - **Security:** XML через `defusedxml.ElementTree` (XXE / billion-laughs / external-DTD → `WsdlImportError`);
    header-injection guard на `SOAPAction`/`action` (drop CR/LF); XML-имена элементов санитайзятся, значения escape'ятся.
  - **Fail-closed:** not-well-formed / root≠`<definitions>` / нет импортируемых SOAP-операций с адресом → `WsdlImportError`.
    Bounded ≤2000 операций, ≤100 parts/envelope. Non-SOAP-биндинги и порты без soap:address пропускаются.
  - **Проверки:** ruff ✅, black ✅, mypy ✅, unit — **12 тестов** (soap11 op+envelope+parts; soap12 ct+action+envelope-ns;
    element-part empty-tag; non-soap-binding-skip; no-address-skip; **XXE-refuse**; **SOAPAction-injection-drop**;
    3× fail-closed: not-well-formed / wrong-root / no-ops); весь `tests/unit/web_workbench` — **407 passed** (+12).

## 11. MACHINE-ACTIONABLE BACKLOG (следующий этап, без заглушек)

Каждая запись — исполнимая единица со списком файлов и критерием готовности.
Порядок отражает зависимости (§5). Реестры НЕ дублировать — расширять существующие.

### WB-P1b — ✅ DONE (см. §10). Следующий вход — WB-P2.

### WB-P2 — Proxy execution-plane (`argus-web-proxy`)

Разбит на 3 подсрезка (каждый отдельно верифицируем). **P2a-1 — DONE** (см. §10).

#### WB-P2a-1 — ✅ DONE (эта сессия). Data-plane core (pure, offline-tested)
`backend/src/web_workbench/proxy/{__init__,transport,ca_manager,intercept_rules,forward_gate}.py`
+ `tests/unit/web_workbench/proxy/*` (37 тестов). Детали — §10.

#### WB-P2a-2 — ✅ DONE (см. §10). Следующий вход — WB-P2b-1.

#### WB-P2b-1 — ✅ DONE (см. §10). CA lifecycle (sealing + issue/rotate + API)

#### WB-P2b-2 — live MITM daemon + Docker + E2E (требует live-инфры)
- **Files:**
  - `backend/src/web_workbench/proxy/service.py` — mitmproxy addon: per-flow `ForwardGate`(scope)+
    полный `PreflightChecker` через `preflight_hook`, `InterceptRuleSet`, `CertificateAuthority.issue_leaf`
    (CA грузится через `load_ca(sealer, cert_pem, sealed_key)` из `ca_lifecycle`), стрим тела через
    `plan_body`→`BodyObjectStore`→`ProxyRepository.persist_message`.
  - `backend/pyproject.toml` — добавить `mitmproxy` (pinned) в опциональную группу `web-proxy`
    (НЕ импортировать `service.py` из `main.py` — демон живёт только в контейнере `argus-web-proxy`).
  - `infra/docker-compose.yml` (+сервис `argus-web-proxy`, pinned image, healthcheck),
    `infra/docker-compose.e2e.yml` (+juice-shop).
- **Инварианты:** каждый forwarded request → `ForwardGate`(scope)+`PreflightChecker`(ownership/policy/
  approval); kill switch (`status=killed` → drop); DNS-rebinding защита; CA приватный ключ только через
  `load_ca`(unseal in-process), НИКОГДА в логах/в API.
- **DoD:** HTTP/1.1+HTTPS MITM E2E против juice-shop — capture/edit/forward/drop; proxy→history;
  benchmark задокументирован; security-test (scope bypass, CA exposure, DNS rebinding).
- **Блокер верификации:** нужен запущенный Docker-стек + `mitmproxy` dependency; код+unit пишутся
  offline, но E2E-DoD подтверждается только на живой инфре.

### WB-P3 — Manual tools (message editor, Repeater, Decoder, Comparer, Organizer)

Разбит на подсрезы (каждый отдельно верифицируем). **P3a — DONE** (см. §10).

#### WB-P3a — ✅ DONE (эта сессия). Decoder + Comparer (pure, offline)
`web_workbench/{decoder,comparer}/*` + API `/wb/tools/{decoder,comparer}` + 30 unit-тестов. Детали — §10.

#### WB-P3b-1 — ✅ DONE (см. §10). Message editor + Repeater scope-gate engine (pure)
`web_workbench/{message_editor,repeater}/*` + `/wb/tools/message-format` + 16 unit-тестов.

#### WB-P3b-2 — ✅ DONE (эта сессия, кроме live-send E2E). Repeater persistence + live sender
- **Files:** модели `WbRepeaterTab` (raw_request byte-exact, scheme/host/port, version), `WbRepeaterExchange`
  (raw_request, forward_outcome, block_reason, status_code, raw_response bounded+truncated, duration_ms) + миграция
  `049_wb_repeater.py` (RLS ENABLE+FORCE); `web_workbench/repeater/repository.py` (RLS + optimistic lock + history);
  `web_workbench/repeater/sender.py` (`HttpxSender` — bounded stream, hop-by-hop strip, no-redirect, verify=off);
  API `/wb/*/repeater/*` (tabs CRUD + replay + history, 8 endpoints); docs §4e; contract-paths.
- **Инварианты ✅:** replay ТОЛЬКО через `RepeaterService`(scope→optional preflight); при block `HttpSender` НЕ вызывается
  (`sender.calls==0` — покрыто integration-тестом); каждый exchange (forward/blocked) в history; raw-override byte-exact;
  kill-switch — replay запрещён если `project.status ≠ active` (409); raw не логируется; response bounded (5 MiB).
- **DoD ✅:** unit — sender через `httpx.MockTransport` (URL/method/headers, framing-strip, bounded/truncated) + mapping
  (11 тестов); alembic smoke; live OpenAPI (5 paths); `ruff`/`black`/`mypy` ✅; весь `tests/unit/web_workbench` — **132 passed**.
  Postgres RLS integration написан (`test_repeater_rls.py`, 3 теста: cross-tenant raw `count(*)`, optimistic lock,
  out-of-scope→blocked-без-send) — **verify на live Postgres** (`requires_postgres`).
- **⏳ Осталось (live-send E2E, infra-gated):** реальный replay endpoint выполняет egress через `HttpxSender` —
  E2E против local target требует сети/target; движок+sender offline-протестированы через MockTransport.

#### WB-P3c — ✅ DONE (эта сессия). Organizer (модели + миграция + API)
- **Files:** модели `WbOrganizerCollection`,`WbOrganizerItem` + миграция `048_wb_organizer.py` (RLS ENABLE+FORCE);
  `web_workbench/organizer/repository.py` (RLS + optimistic lock + поиск tag/host/title); `contracts/organizer.py`;
  API `/wb/*/organizer/*` (collections+items CRUD, 10 endpoints); docs §4d; contract-paths.
- **Инварианты:** cross-tenant RLS-изоляция (raw `count(*)`); raw-байты byte-exact и не логируются;
  raw возвращается ТОЛЬКО в single-item GET; tags дедуп/трим; поиск tag=JSONB containment, q=title ilike.
- **DoD ✅:** unit mapping/контракты (5); alembic smoke round-trip; live OpenAPI (5 paths); `ruff`/`black`/`mypy` ✅;
  весь `tests/unit/web_workbench` — **121 passed**. Postgres RLS integration написан
  (`tests/integration/web_workbench/test_organizer_rls.py`, 3 теста) — **verify на live Postgres** (`requires_postgres`).

### WB-P4 — Intruder (Sniper/Battering ram/Pitchfork/Cluster bomb)

Разбит на 2 подсреза. **P4a — DONE** (см. §10): чистое ядро генерации/анализа, offline.

#### WB-P4a — ✅ DONE (эта сессия). Attack core (positions + strategies + processors + analysis, pure)
- **Files:** `web_workbench/intruder/{positions,processors,strategies,analysis,engine}.py` + `__init__`.
  positions — parse/render byte-exact ({{…}}-маркеры, base-value round-trip); strategies — Sniper/Battering-ram/
  Pitchfork/Cluster-bomb + `total_requests`/budget cap; processors — prefix/suffix/encode(url/base64/hex/html)/
  hash(md5/sha1/sha256)/regex_replace (bytes-chain); analysis — grep-match/extract + dedup.
- **Инварианты ✅:** payload sets — вход (источник ТОЛЬКО `PayloadRegistry`/`PayloadBuilder`, SI-5; движок их не тянет);
  processors применяются к payload, base-value untouched (byte-fidelity); нет I/O/сети/БД; budget-cap (`MAX_TOTAL_REQUESTS`).
- **DoD ✅:** 4 стратегии + processors + grep-match/extract + dedup unit-tested (**40 тестов**);
  `ruff`/`black`/`mypy` ✅; весь `tests/unit/web_workbench` — **172 passed**.

#### WB-P4b — Intruder execution (persist + worker + evidence, infra-gated) — pending
- **Files:** модели `WbIntruderAttack`,`WbIntruderRequest`/result + миграция `050`; `web_workbench/intruder/service.py`
  (gate каждого запроса через scope+preflight+EAP-budget); отдельный Celery worker pool (`argus.intruder.highvol`) с
  quotas+kill switch; API `/wb/projects/{id}/intruder/*` (create/start/pause/resume/cancel/results); мост результатов →
  evidence → `FindingDTO` через `finding_bridge`.
- **Инварианты:** payload sets ТОЛЬКО через `PayloadBuilder` (materialize из реестра); high-volume/race/single-packet
  → risk-класс + EAP; request budget из EAP; каждый запрос проходит `ForwardGate`; kill-switch по project status.
- **DoD:** persistence RLS integration; pause/resume/checkpoint/cancel; live high-volume E2E — **infra-gated**.

#### WB-P4 (исходные требования, покрываются P4a+P4b)
- **DoD:** 4 стратегии + processors (encode/hash/prefix/regex) unit-tested; grep-match/extract; dedup;
  pause/resume/checkpoint/cancel; результаты → evidence → `FindingDTO`.

### WB-P5 — Scanner / Crawler / Live Audit (расширять, НЕ дублировать)

Разбит на 2 подсреза. **P5a — DONE** (см. §10): чистый passive-анализатор захваченного трафика, offline.

#### WB-P5a — ✅ DONE (эта сессия). Passive HTTP audit analyzer (pure, offline)
`web_workbench/passive/{__init__,analyzer.py}` + `tests/unit/web_workbench/passive/*` (13 тестов). Детали — §10.
Native passive-checks (security headers / cookies / info-disclosure / CORS / reflected-input), findings в таксономии
платформы (`FindingCategory`/`ConfidenceLevel`) для чистого моста в `FindingDTO`. НЕ дублирует Nuclei.

#### WB-P5b-1 — ✅ DONE (эта сессия). Scanner persistence models + passive→FindingDTO bridge (offline)
`WbScannerTask`/`WbScannerIssueLink` + миграция `050_wb_scanner.py` (RLS, head=050 single);
`web_workbench/passive/finding_bridge.py` (чистый `PassiveFinding`→`FindingDTO`, code→CWE/severity→CVSS/tier,
fail-closed) + 20 unit-тестов. Детали — §10.

#### WB-P5b-2 — Scanner orchestrator + crawler + Nuclei→FindingDTO + OAST bridge + API (infra-gated) — pending
- **Files:** `backend/src/web_workbench/scanner/*` (task orchestrator: crawl/audit, checkpoint, cancel/kill через
  `status=cancelled`); `web_workbench/scanner/repository.py` (RLS + optimistic lock над `WbScannerTask`/
  `WbScannerIssueLink`); мост `passive.analyze()`→evidence→`FindingDTO` (через готовый `finding_bridge`) →
  persist + `WbScannerIssueLink`; расширение `nuclei_va_adapter.py` (per-request/host/path, фильтры шаблонов,
  live progress, cancel — НЕ второй pipeline); интеграция OAST через существующий `src/oast/correlator.py`
  (переиспользовать, не форкать) → `FindingDTO`; API `/wb/projects/{id}/scanner/*` (create/start/pause/resume/
  cancel/results); Celery worker для active scan.
- **Инварианты:** active scan ТОЛЬКО через ForwardGate+preflight+EAP; passive-findings (tier ≤ SUSPECTED, status NEW)
  требуют FP-verifier перед промоушеном; NO второй Nuclei pipeline (grep-проверка); OAST-коррелятор не форкается;
  kill-switch по `project.status`/`task.status`.
- **DoD:** passive scan proxy-трафика (RLS integration); active scan через playbooks/oracles; FP verifier;
  Nuclei→FindingDTO без дублей; OAST token→interaction→finding integration test — **infra-gated** (Postgres/Celery/сеть).

### WB-P6 — Multi-principal SessionStore (persist) + Auth Analyzer + DOM instrumentation

Разбит на 2 подсреза. **P6a — DONE** (см. §10): чистый authorization-analyzer поверх `AuthzOracle`, offline.

#### WB-P6a — ✅ DONE (эта сессия). Authorization analyzer (owner/attacker/anon diff → BAC/IDOR, pure)
`web_workbench/checks/{__init__,authorization_analyzer.py}` + `tests/unit/web_workbench/checks/*` (16 тестов).
Тонкий offline-адаптер поверх `playbooks.oracles.AuthzOracle` (переиспользование), классификация IDOR/BFLA/UNAUTH,
SI-3 (finding без raw-тел). Детали — §10.

#### WB-P6b — SessionStore persist + live owner/attacker replay + DOM instrumentation + FindingDTO (infra-gated) — pending
- **Files:** `SessionPrincipal`,`SessionMacro` модели + миграция `051`; `web_workbench/sessions/*` (split-plane
  secrets через `secrets_ref`, macro-replay для логина); live owner/attacker/anon replay-раннер (использует P6a
  `analyze_authorization` над реально снятыми парами) + мост `AuthorizationFinding`→`FindingDTO` (category AUTH/IDOR);
  расширение `playwright_adapter.py` (reusable context для atomic actions, DOM source/sink, postMessage, CSP).
- **Инварианты:** split-plane secrets (SI-3), redaction через `auth/redaction.py`+`playbooks/evidence`; replay ТОЛЬКО
  через ForwardGate+preflight+EAP; P6a-анализатор — вход (уже offline-верифицирован).
- **DoD:** owner-vs-attacker diff E2E; secret-leakage security test; BAC/IDOR классификация → FindingDTO — **infra-gated**.

### WB-P7 — Native BApp-modules (behavioral parity, с provenance)

**P7a — DONE** (см. §10): `client_dependency` (Retire.js-подобный, pure, offline). Остальные модули — pending.

#### WB-P7a — ✅ DONE (эта сессия). Client dependency scanner (`client_dependency`, pure)
`web_workbench/checks/client_dependency.py` + `tests/.../test_client_dependency.py` (16 тестов). Курированный
CVE-датасет (6 библиотек), detect→match→`FindingDTO`(SUPPLY_CHAIN). Детали — §10.

#### WB-P7b — `jwt_editor` (pure JWT inspector) — ✅ DONE (эта сессия)
`web_workbench/checks/{severity.py,jwt_editor.py}` + `tests/.../test_jwt_editor.py` (16 тестов). alg-none/jwk/jku/x5u/
kid-injection/exp/sensitive-claim → `FindingDTO`(JWT). Общий `severity.py` (CheckSeverity+cvss_for). Детали — §10.

#### WB-P7c — `nosqli` (pure NoSQLi passive analyzer) — ✅ DONE (эта сессия)
`web_workbench/checks/nosqli.py` + `tests/.../test_nosqli.py` (24 теста). operator-injection (bracket/token/JSON/
urlencoded) + error-signature (переиспользует `DETECTION_SIGNATURES["nosql"]`) → `FindingDTO`(NOSQLI, CWE-943).
Детали — §10.

#### WB-P7d — `wordpress` (pure passive CMS analyzer) — ✅ DONE (эта сессия)
`web_workbench/checks/wordpress.py` + `tests/.../test_wordpress.py` (21 тест). Пассивный fingerprint
(`/wp-content`, X-Pingback, api.w.org Link, `wordpress_*` cookie), version-disclosure (generator-meta/feed/
readme.html), user-enum (wp-json/wp/v2/users + ?author→/author/), xmlrpc-enabled, debug.log-exposed (SECRET_LEAK),
directory-listing → `FindingDTO` (per-finding category: INFO/MISCONFIG/SECRET_LEAK). Secret-free evidence
(только маркер/endpoint, без значений cookie/slug/username); CONFIRMED только для response-proven сигналов. Детали — §10.

#### WB-P7e — Активные native-модули (pending, infra-gated)
- **Modules:** `active_scan_plus`, `param_miner`, `request_smuggler` — активная отправка crafted-запросов
  (raw transport + risk-класс + local E2E only) — **требуют live-инфры + ForwardGate + EAP**.
- **Files:** `web_workbench/checks/*`; новые payload-семейства в `config/payloads/**` (дедуп + re-sign
  `payloads_sign.py` + drift-test); provenance-записи (repo URL, commit SHA, license, NOTICE).
- **DoD:** каждый модуль: strict evidence + negative fixtures; payload drift/dedup зелёные;
  smuggling/desync только против local target с EAP. Все три требуют live-инфры.

### WB-P8 — Extension platform + declarative check DSL

Разбит на срезы. **P8a — DONE** (offline DSL-ядро, см. §10).

#### WB-P8a — Declarative check DSL (BCheck-подобный, pure) — ✅ DONE (эта сессия)
`web_workbench/extensions/{__init__,check_dsl.py}` + `tests/.../extensions/test_check_dsl.py` (27 тестов).
Data-only схема (fail-closed `extra=forbid`+frozen, как playbooks): `DeclarativeCheck` (metadata/category/severity/
confidence/cwe/scope/requires_oast/remediation) + `MatcherGroup`(AND/OR) из `Matcher`(part×kind: contains/regex/
equals/status, negate, case_sensitive) + `Extractor`(capped capture). Чистый `evaluate_check`/`evaluate_checks`
над `NormalizedRequest`/`NormalizedResponse`, OAST-gated (fail-closed без `oast_confirmed`), scan-cap 512 KiB,
regex-len ≤512. Мост `check_finding_to_dto`→`FindingDTO`; `load_check` — fail-closed (`DslError`, без stack-trace).
Переиспользует `checks/severity.py`. Детали — §10.

#### WB-P8b-1 — Manifest schema + signing CLI (pure, offline) — ✅ DONE (эта сессия)
`src/web_workbench/extensions/manifest.py` + `scripts/extension_sign.py` + `tests/.../extensions/test_manifest.py`
(21 тест). `ExtensionManifest` (fail-closed, embedded `DeclarativeCheck` через P8a) с least-privilege инвариантами
(perms↔checks) + `verify_and_load` (Ed25519 verify ПЕРЕД парсингом) + CLI (mirror `prompts_sign.py`). Детали — §10.

#### WB-P8b-2 — Extension registry + persist + isolation (pending, infra-gated)
- **Files:** `ExtensionInstallation`/`ExtensionManifestRow` модели + миграция `051`;
  `web_workbench/extensions/{registry,loader,host}.py` (signed-manifest verify через готовый `verify_and_load` +
  DSL-check eval через P8a `evaluate_checks`); admin-frontend governance UI.
- **Инварианты:** isolated process/container/WASM, resource quotas, egress policy, secret_ref permissions,
  rollback, audit; манифест-verify + least-privilege — **уже offline-закрыты в P8b-1**.
- **DoD:** extension hook isolation integration test; malicious/unsigned manifest security test (reject);
  все hooks (§5 ТЗ) реализованы. Requires live-инфра (Postgres RLS + процесс-изоляция).

### WB-P9 — AI prompts + MCP — ⛔ KEY/INFRA-GATED (не offline)
- **Блокер (prompt-каталог):** `config/prompts/SIGNATURES` подписан приватным Ed25519-ключом
  (`681a1d103f2d8759`), в репо только публичный ключ. Добавление workbench-промптов требует re-sign через
  `prompts_sign.py --sign --key <PRIV>` (приватный ключ недоступен) — иначе fail-closed `PromptRegistry.load`
  и `test_signed_prompts_load`/drift-тесты падают. Плюс `AgentRole` — закрытый enum (planner/critic/verifier/
  reporter/fixer): новые роли трогают trust-boundary оркестратора и его тесты. **Нельзя закрыть offline без
  приватного ключа и согласованного расширения AgentRole.**
- **Files:** `config/prompts/*` (+24 workbench-промпта, strict JSON schema, injection fixtures, re-sign
  `prompts_sign.py`); `src/mcp/{schemas,services,tools}/web_*` (§9 ТЗ tools/resources/prompts);
  `export_mcp_openapi` → `docs/mcp-server-openapi.yaml` → `Frontend npm run sdk:generate` (ТОЛЬКО SDK,
  не менять Frontend-код) → `sdk:check`.
- **Инварианты:** MCP mutations tenant-scoped/RBAC/rate-limited/scope+EAP-checked/audit/idempotent/redacted.
- **DoD:** MCP→service→audit integration test; prompt-injection regression fixtures; SDK drift-check зелёный;
  docstrings ≥30 chars (существующий CI-гейт). Requires signing key + live MCP/SDK toolchain.

### WB-P10 — Pentest Mapper / checklists / reports / imports / connector

Разбит на срезы. **P10a — DONE** (HAR importer, offline). **P10b — DONE** (OpenAPI/Swagger importer, offline).
**P10c — DONE** (Postman Collection v2.1 importer, offline). **P10d — DONE** (GraphQL introspection importer, offline).
**P10e — DONE** (WSDL 1.1 importer, offline).

#### WB-P10a — HAR importer (pure, offline) — ✅ DONE (эта сессия)
`src/web_workbench/imports/{__init__,har.py}` + `tests/.../imports/test_har.py` (18 тестов). `import_har` →
`list[ImportedExchange]` на базе `NormalizedRequest`/`NormalizedResponse` (импортированный трафик = live-трафик для
proxy history / Repeater / passive / DSL). Fail-closed (`HarImportError`), bounded (20k entries / 5 MiB body +
`truncated`), header-injection guard, base64-тела, no-response для failed-запросов. Детали — §10.

#### WB-P10b — OpenAPI/Swagger importer (pure, offline) — ✅ DONE (эта сессия)
`src/web_workbench/imports/{__init__,openapi.py}` + `tests/.../imports/test_openapi.py` (16 тестов).
`import_openapi(raw, *, base_url=None)` → синтетические `ImportedExchange` (по одному на операцию, `response=None`)
для OpenAPI 3.x и Swagger 2.0 (JSON/YAML). Host-резолв (base_url→servers→schemes/host/basePath), sample-значения
(example→enum→тип), path/query/header params + JSON requestBody, fail-closed (`OpenApiImportError`), bounded
(≤5000 операций), header-injection guard. Детали — §10.

#### WB-P10c — Postman Collection v2.1 importer (pure, offline) — ✅ DONE (эта сессия)
`src/web_workbench/imports/{__init__,postman.py}` + `tests/.../imports/test_postman.py` (20 тестов).
`import_postman(raw, *, variables=None)` → синтетические `ImportedExchange` (request-only) для Postman v2.1
(JSON/YAML): nested-folders, string/object url, `{{var}}`-резолв (collection+url+override), body-modes
raw/urlencoded/formdata, header/CR-LF-guard, fail-closed (`PostmanImportError`), bounded. Переиспользует
`har`-хелперы (DRY). Детали — §10.

#### WB-P10d — GraphQL introspection importer (pure, offline) — ✅ DONE (эта сессия)
`src/web_workbench/imports/{__init__,graphql.py}` + `tests/.../imports/test_graphql.py` (16 тестов).
`import_graphql_introspection(raw, *, endpoint_url)` → синтетические `POST`-`ImportedExchange` (`{"query":…}`) на
каждое корневое `Query`/`Mutation`-поле: depth-bounded selection-set, scalar/enum arg-сэмплы, анти-цикл,
non-scalar-arg-skip, fail-closed (`GraphQLImportError`), bounded. Переиспользует `har`-хелперы. Детали — §10.

#### WB-P10e — WSDL 1.1 importer (pure, offline) — ✅ DONE (эта сессия)
`src/web_workbench/imports/{__init__,wsdl.py}` + `tests/.../imports/test_wsdl.py` (12 тестов). `import_wsdl(raw)` →
синтетические SOAP `POST`-`ImportedExchange` на каждую binding-операцию с адресом: SOAP 1.1/1.2 envelope+headers,
RPC/document parts, XXE-safe (`defusedxml`), header-injection guard, fail-closed (`WsdlImportError`), bounded.
Переиспользует `har`-хелперы. Детали — §10. **Все offline-импортёры (HAR/OpenAPI/Postman/GraphQL/WSDL) закрыты.**

#### WB-P10f — Checklists + connector (pending, infra-gated)
- **Files:** `ChecklistDefinition`,`ChecklistExecution` модели + миграция; `web_workbench/checklist/*`;
  WSTG/ASVS/API-Top10 coverage (расширить существующий WSTG registry, НЕ дублировать);
  `web_workbench/integrations/pentest_tools.py` (secret_ref token, retry/circuit breaker, redaction, feature flag,
  mocked contract tests).
- **DoD:** flow↔checklist mapping; coverage dashboard в admin-frontend; report coverage section;
  connector contract-tests зелёные. Checklist persist + connector — infra-gated (Postgres RLS + сеть/секреты).

### WB-P11 — E2E / security / load / docs / final audit
- **DoD:** полный E2E против docker-compose.e2e (juice-shop/WebGoat); security-review (§12 ТЗ);
  load/resilience; docs (architecture, operator guide, proxy CA setup, EAP, extension dev,
  payload/check authoring, MCP usage, kill-switch runbook, migration/rollback); Definition of Done (§14).
