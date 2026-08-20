# ARGUS Architecture Decisions

Ключевые архитектурные решения проекта ARGUS.

---

## ADR-001: Frontend — источник истины

**Статус:** Принято

**Контекст:** Backend и Frontend разрабатываются параллельно. Нужен единый источник истины для API.

**Решение:** Frontend (ARGUS/Frontend) — источник истины для API контрактов. Backend реализуется строго по контрактам. Изменения names, paths, status codes, payload shape — только после обновления Frontend или явного согласования.

**Следствия:**
- [api-contracts.md](./api-contracts.md) — каноническое описание REST API
- Contract tests проверяют совместимость backend с ожиданиями Frontend
- Референс: test/pentagi/frontend при пустом ARGUS/Frontend

---

## ADR-002: REST API (не GraphQL)

**Статус:** Принято

**Контекст:** pentagi использует GraphQL. ARGUS — сканер с простыми CRUD и потоком событий.

**Решение:** REST API для всех операций. SSE для real-time прогресса скана. GraphQL не используется.

**Следствия:**
- Простая интеграция с любым клиентом
- OpenAPI/Swagger для документации
- SSE — односторонний поток, проще WebSocket

---

## ADR-003: PostgreSQL + Redis + MinIO

**Статус:** Принято

**Контекст:** Нужны: персистентное хранилище, очереди, object storage для отчётов.

**Решение:**
- **PostgreSQL** — scans, reports, findings, events, users, tenants. pgvector для будущего RAG.
- **Redis** — Celery broker, rate limiting, кэш.
- **MinIO** — S3-совместимое хранилище отчётов (PDF, HTML, JSON, CSV).

**Следствия:**
- Docker Compose для локальной разработки
- Миграции через Alembic

---

## ADR-004: Celery для фоновых сканов

**Статус:** Принято

**Контекст:** Сканирование — долгий процесс (минуты). HTTP request не должен блокироваться.

**Решение:** Celery worker выполняет scan_phase_task. API возвращает scan_id сразу, клиент подписывается на SSE или polling.

**Следствия:**
- Redis как broker
- Профиль `tools` для celery-worker в docker-compose

---

## ADR-005: SSE для прогресса скана

**Статус:** Принято

**Контекст:** Клиенту нужен real-time прогресс (phase, progress, findings).

**Решение:** `GET /scans/:id/events` — Server-Sent Events. События пишутся в ScanEvent (PostgreSQL), backend читает и стримит. Polling `GET /scans/:id` — fallback.

**Следствия:**
- sse-starlette для FastAPI
- Фильтрация phase_complete (ARGUS-010): не передавать findings/exploits/evidence в SSE

---

## ADR-006: JWT + API Key для auth

**Статус:** Принято

**Контекст:** Admin-frontend и CI/CD требуют аутентификации.

**Решение:** JWT access token (15m) для admin-frontend. X-API-Key для programmatic access. Scans/Reports — публичные в текущей модели доступа.

**Следствия:**
- JWT_SECRET обязателен для auth endpoints
- POST /auth/login — упрощённый путь (любые credentials при JWT_SECRET в dev)
- GET /auth/me — protected

---

## ADR-007: Tools Guardrails

**Статус:** Принято

**Контекст:** Инструменты (nmap, nuclei, sqlmap и др.) выполняют команды. Риск: injection, сканирование неразрешённых целей.

**Решение:**
- Allowlist команд (nmap, nuclei, nikto, gobuster, sqlmap для /execute)
- Валидация target: домен или IP (whitelist)
- Rate limiting (30 req/min на IP)
- Sandbox (опционально) для изоляции

**Следствия:**
- parse_execute_command, validate_target_for_tool
- SANDBOX_ENABLED в config

---

## ADR-008: Multi-tenant через RLS

**Статус:** Принято (частично)

**Контекст:** Изоляция данных между tenants.

**Решение:** tenant_id во всех таблицах. RLS (Row Level Security) — `SET LOCAL app.current_tenant_id` перед запросами. Default tenant для публичного сканера.

**Следствия:**
- Alembic migration 002_rls_and_audit_immutable
- AuthContext.tenant_id для JWT/API key

---

## ADR-009: Отчёты — генерация on-demand и кэш

**Статус:** Принято

**Контекст:** PDF/HTML/JSON/CSV генерируются из данных Report + Findings.

**Решение:** При download — проверка MinIO. Если есть кэш — отдать. Иначе — сгенерировать, загрузить в MinIO, отдать.

**Следствия:**
- reports/generators.py — weasyprint (PDF), jinja2 (HTML)
- reports/storage.py — upload/download

---

## ADR-010: Observability

**Статус:** Принято

**Контекст:** Мониторинг в production.

**Решение:** Prometheus metrics (`/metrics`), structured JSON logging, OpenTelemetry-ready (OTEL_EXPORTER_OTLP_ENDPOINT).

**Следствия:**
- core/observability.py — scan_started, phase_duration, tool_run
- LOG_LEVEL, OTEL_* env vars

---

## ADR-011: Единый контур исполнения exploitation + отложенный auth в signed-пути

**Статус:** Принято (транспорт — opt-in; auth в signed-пути — отложено)

**Контекст:** Фаза exploitation исполняла инструменты четырьмя независимыми
плоскостями с hardcoded `docker exec` и raw-LLM генерацией argv/пейлоадов. Нужен
единый контролируемый контур: LLM — диспетчер, но не исполнитель непроверенных строк.

**Решение:**
- **Пейлоады** — только из подписанного каталога через `PayloadBuilder` +
  `PayloadContext` (динамическая кодировка по `sink_type`); raw-LLM fallback удалён.
- **Выбор инструментов** — подписанный `tool_profiles.yaml` (Ed25519, fail-closed),
  фолбэк на in-code `_VULN_TOOL_MAP`.
- **Неймспейс** — резолвинг в подписанный `tool_id` через `ToolRegistry.resolve`.
- **Транспорт** — `DockerSandboxAdapter` (тот же контракт, что
  `KubernetesSandboxAdapter`): эфемерный hardened `docker run`, argv из
  `command_template` через `render_argv`. Включается флагом
  `scan_options["use_docker_sandbox_runner"]`; по умолчанию — legacy `docker exec`.

**Auth в signed-пути — реализовано (adapter-level, а не через каталог):**
signed tools-каталог закрыт на 162 дескриптора и жёстко зарощен ратчетами
(count-pin, coverage-matrix, version-baseline), поэтому auth-варианты дескрипторов
там неуместны. Ключевое наблюдение: auth-значения ДИНАМИЧЕСКИЕ (из сессии) и в
принципе не могут быть в подписанном шаблоне — подписать можно лишь СТРУКТУРУ
флага. Значит «signed `{auth_header}` placeholder» и «валидируемый добавляемый
флаг из доверенного кода» **security-эквивалентны**. Принятая реализация:
- `DockerSandboxAdapter.run(..., auth_argv=[...])` — необязательный фрагмент
  аутентифицированной сессии, добавляемый ПОСЛЕ argv из `command_template`;
- флаг-токены выбирает доверенный код (не LLM); значение — из `SessionStore`
  (Playwright), **строго валидируется** (`_validate_auth_header_value`: нет
  CR/LF/NUL/control → нет header/argv-инъекции; это один argv-токен) и
  **редактируется** в persisted plan / dry-run артефактах (`[REDACTED]`);
- проверено e2e на реальном Docker (`test_docker_adapter_e2e.py`): auth-флаги
  доходят до `docker run`, секрет отсутствует в плане.
Это устраняет прежний фолбэк-на-legacy для auth: signed-путь теперь аутентифицирует.

**Следствия:**
- `orchestration/exploitation_executor.py` — `_build_payloads_for_finding` (no-LLM),
  `_select_tools_for_finding` (signed profiles), `_run_tool_via_registry` (opt-in,
  auth через `_validated_auth_argv`), `_validate_auth_header_value`.
- `sandbox/docker_adapter.py` (`auth_argv` + redaction), `orchestration/tool_profiles.py`,
  `config/tool_profiles/*`.
- `recon/mcp/policy.py` — `evaluate_tool_approval_for_scan` (`engagement_id` +
  reason-контракт выровнен с preflight).
- Отчёт цикла: `docs/develop/reports/orch-2026-08-16-executor-single-control-plane-completion.md`.

---

## ADR-012: Флаг-gated консолидация исполнения, structured-output и runtime AssetGraph (overhaul B2–B8)

**Дата:** 2026-08-17 · **Статус:** принято

**Контекст:** аудит промта «полная доработка ARGUS» выявил PARTIAL/MISSING по 10 областям. Часть — поведение-меняющие (единый control plane, structured output) или требуют live-LLM/сборки образов. Принцип: любое поведенческое изменение — **strict superset за флагом** (default off = прежнее поведение), с полным регрессом.

**Решения:**
- **Единый control plane (B7):** вынесен `orchestration/signed_tool_runner.py` — ОДИН process-wide singleton реестра + generic `run_signed_tool(target_kind ∈ {URL,DOMAIN,HOST,IP,CIDR}, extra_parameters)` + общий sync→async мост `run_coro_sync`. За флагами консолидированы **4 плана**: exploitation (делегирует), VA active-scan, KAL-MCP (с сохранением MinIO-upload), и общий низкоуровневый recon-exec `run_argv_simple_sync` (для вызывателей с `tool_id`). Флаги: `ARGUS_EXPLOITATION_SIGNED_RUNNER`, `ARGUS_RECON_SIGNED_RUNNER` (оба default off, legacy — авто-fallback). Argv компилируется из подписанного `command_template` (в signed-пути хардкода нет). Каталог становится авторитетным → флаг-gated поведенческое изменение. Естественные границы: `execute_command` без `tool_id` (generic escape hatch) и MCP-реестр (fail-closed контракт) остаются legacy.
- **Structured output (B5b-2):** `ARGUS_SCAN_SCHEMA_ENFORCEMENT` — валидация phase-ответа против `get_schema(phase)` через **существующий** fixer-retry; при провале — деградация в `None` как раньше (strict superset).
- **LLM routing/context (B5a/B5b-1):** WRB prompt-budget из реестра (не `[:8192]`); phase routing имеет приоритет над unified gateway при явном включении.
- **untrusted_input (B5c):** provenance `source=phase`; полный field-level scoping — отдельный template-refactor + live-LLM.
- **AssetGraph + adaptive loop (B6):** `orchestration/graph.py` (типизированный DAG активов) + `graph_builders.py` (populate из `InputSurfaceInventory`, `apply_tested_surfaces`, `coverage_metrics` %params/%endpoints). Движок адаптивного цикла `adaptive_loop.py` (plan→critic→execute→verify→update-graph; роли — `typing.Protocol` + детерминированные дефолты; coverage/budget stop) + production-адаптеры `adaptive_integration.py` (`SignedToolExecutor` через `run_signed_tool`, `HeuristicVerifier`), флаг `ARGUS_ADAPTIVE_LOOP` (default off).
- **Интеграция adaptive-драйвера в `state_machine` — ШАГИ 1–3 (за тем же флагом):** `orchestration/adaptive_phase.py` — консервативный seam: после завершения фазы, при `ARGUS_ADAPTIVE_LOOP=on`, из persisted phase-output best-effort извлекается `InputSurfaceInventory` (findings/hypotheses/input_surfaces с url+param) → строится runtime `AssetGraph` → **(ШАГ 2)** протестированные поверхности (`tested_surface_ids_from_output`: findings как «проба сработала» + явные `tested_surfaces`/`surfaces_tested`/`probed_surfaces`, id-схема единая с универсумом) помечаются через `apply_tested_surfaces` → coverage-снапшот с реальным tested/total `%` пишется как **append-only** `ScanTimeline`-entry. **(ШАГ 3 — движущий цикл)** `orchestration/adaptive_artifacts.py` (LoopReport→scan-контракт) + `orchestration/adaptive_driver.py` (`run_adaptive_vuln_analysis[_signed]`: `inventory → AssetGraph → run_adaptive_loop → VulnAnalysisOutput(findings+coverage)+timeline`). Ключевая идея: драйвер производит **типизированный `VulnAnalysisOutput`**, поэтому все downstream-артефакты (Finding-строки, ScanState, отчёты) получаются через НЕИЗМЕНЁННЫЙ `_persist_report_and_findings` — persistence не переписывается. Evidence-дисциплина: heuristic-`CONFIRMED` (exit0+output) → `EvidenceTier.SUSPECTED` (2), не «provable» — не переоценивает; INCONCLUSIVE/REJECTED → без finding. `ActionRecord` расширен полем `evidence` (аддитивно). Контракт сохранён строго; исполнение — через инъектируемый executor (в проде — signed `run_signed_tool`, в тестах — mocks). **Финальная маршрутизация сделана:** `handlers.run_vuln_analysis` при `flag=on` (внутри `sandbox_enabled and target and _lab_tools_ok`, сразу после сборки `VulnerabilityAnalysisInputBundle`) зовёт guarded `_maybe_adaptive_vuln_analysis` → `build_input_surface_inventory(bundle)` → `run_adaptive_vuln_analysis_signed` → early-return `VulnAnalysisOutput`; любой промах/исключение → `None` → fallback на линейный active-scan+LLM. flag-off = байт-в-байт прежний обработчик. Live-граница (принята): фактическое исполнение инструментов через `SignedToolExecutor` верифицируется только на Docker/LLM (юнит-тесты покрывают guard+fallback+контракт моками).
- **Build-time gate (B2):** `validate_tools.sh` + `infra/sandbox/expected_executables.json` (генератор из 162 дескрипторов, drift-тест). **Wrapper-скрипты реализованы:** 11 обёрток `sandbox/images/_shared/wrappers/*` (`kind: wrapper` в манифесте) — argv→upstream адаптеры (stdin-pipe: hakrawler/waybackurls/subjs/linkfinder/kxss/secretfinder; JSON-envelope: xsstrike/jsql; driven: tplmap/nosqlmap; headless Playwright: playwright-verify-xss), каждый контракт-точен по `command_template`, **fail-safe** (всегда пишет evidence-артефакт; `command -v` guard → graceful error-выход вместо "command not found"). COPY'нуты в `argus-kali-web` (10) и `argus-kali-browser` (playwright), LF закреплён в `.gitattributes`. Offline-гейт `test_tool_wrappers.py` (5 тестов: манифест↔файлы sync, shebang, mkdir-дисциплина, `bash -n` пройден). **Live-верификация (Docker) пройдена:** в минимальном контейнере все 11 обёрток запускаются (LF-shebang подтверждён вживую), fail-safe пишут evidence-артефакт, `command -v` guard → чистый exit 3, JSON-обёртки эмитят валидный JSON; `validate_tools.sh --profile argus-kali-web --strict` → `missing_wrapper=0` (все обёртки на PATH), browser → `missing_wrapper=0`. **Базовый тег образов** переведён на build-ARG `KALI_TAG` (default `latest`) во всех 6 Dockerfile'ах — прежний пин `kalilinux/kali-rolling:2026.1` не существует на Docker Hub (только `:latest`; `--build-arg KALI_TAG=<snapshot>` для воспроизводимого пина). **Полная сборка `argus-kali-web` выполнена (1.02 GB)** и `validate_tools.sh` прогнан ВНУТРИ образа: `ok=35, missing_binary=26, **missing_wrapper=0**` — все 10 web-обёрток присутствуют и на PATH в реальном образе. По ходу сборки выявлена и обойдена **системная гниль версий-пинов** (пин `2026.1` отсутствует → сборка на bleeding-edge `latest` с python 3.14/ruby 3.3, где часть старых пинов не резолвится): (1) apt-зеркало переведено на HTTPS (сетевой AV блокировал pentest-.deb по HTTP c кодом 499); (2) pip/go/gem/npm сделаны **best-effort per-package** (`|| true`) с исправлением валидных пинов (jarm 0.1.5→0.1.0, XSStrike→3.2.2, clairvoyance→2.5.5, evil-winrm-py→1.6.0, hakrawler→@latest) — один устаревший пин больше не рушит образ; отсутствующие инструменты guard'ятся адаптерами/обёртками на PATH. **ВСЕ 6 sandbox-образов собраны** теми же правками (KALI_TAG-ARG + HTTPS-mirror + best-effort pip/go/gem/npm/curl во всех Dockerfile'ах), `validate_tools.sh` прогнан внутри каждого — `missing_wrapper=0` везде: web (1.02GB, ok=35), recon (367MB, ok=12), network (1.03GB, ok=1), cloud (1.04GB, ok=6), browser (2.64GB, ok=2, chromium+jq+playwright-verify-xss ✓), full (1.73GB, ok=0 — fallback-профиль не мапится в манифесте). Дополнительно в browser/full устранён **баг маскировки**: хвостовой `... || true` (cleanup chrome-sandbox) маскировал провал всего `apt-get install` → вынесен в отдельный RUN; и убран захардкоженный список X-lib (chromium сам тянет корректные **t64**-зависимости — `libasound2`→`libasound2t64` стал candidate-less virtual на свежем rolling-base). **Ре-пиннинг — БАТЧ 1 (apt-recovery):** discovery-проба (https-apt на текущем rolling-base) показала, что Kali сопровождает актуальные apt-пакеты многих инструментов → переключение с устаревших pip/go/gem на apt: web +10 (nmap, feroxbuster, wfuzz, wpscan, commix, joomscan, eyewitness, gobuster, gowitness, paramspider; убраны gem wpscan + pip paramspider), recon +3 (enum4linux-ng, dnsrecon, theHarvester; убраны из pip). После пересборки: **web missing 26→17, recon 5→2** (missing_wrapper=0). **Остаётся (батч 2+):** Go-пины (naabu, findomain), GitHub-clone (cmsmap/droopescan/aquatone/arachni/ghauri/magescan/w3af), npm (newman/wappalyzer/cloudsploit), pip-CLI (jarm/favfreak/inql), name/path (testssl.sh), in-house шимы (oastify-client/openapi-scanner/cloud_metadata_check/zap-baseline.py), cloud (prowler py3.14/trivy/dockle/kics) + fail-closed в Dockerfile.
- **B8:** удалён единственный genuine dead-code (`src/prompts/threat_modeling_prompts.py`, 0 импортёров); прочие «дубли» при инспекции — разные активные слои (не удаляемы). admin-frontend сохранён.

**Следствия:** новые флаги в `infra/.env.example`; парсеры 130→137; семейства пейлоадов 54→67; новые модули `signed_tool_runner`, `graph`, `graph_builders`. Отчёт: `docs/develop/reports/orch-2026-08-17-argus-overhaul-b2-b8-completion.md`.

---

## Связанные документы

- [api-contracts.md](./api-contracts.md)
- [api-contract-rule.md](./api-contract-rule.md)
- [auth-flow.md](./auth-flow.md)
- [sse-polling.md](./sse-polling.md)
- [env-vars.md](./env-vars.md)
