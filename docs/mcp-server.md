# ARGUS MCP Server

**Version:** 1.0 (ARG-023, Backlog/dev1_md §13)
**Code:** `backend/src/mcp/server.py`, `backend/src/mcp/{tools,resources,prompts,services}/`
**Tests:** `backend/tests/{unit,integration}/mcp/`

В документе описаны два MCP-сервера:

| # | Сервер | Файл | Назначение |
|---|--------|------|-----------|
| **A** | **Backend MCP server** (текущая версия, ARG-023) | `backend/src/mcp/server.py` | LLM-фасад над scan / findings / approvals / report / policy / scope. JSON-RPC через `stdio` + `streamable-http`. |
| **B** | **Legacy KAL HTTP proxy** | `mcp-server/argus_mcp.py` + `POST /api/v1/tools/kal/run` | Категорийные обёртки Kali (`run_network_scan`, `run_web_scan`, …). Оставлены для обратной совместимости. |

> Если вы интегрируете LLM-агента (Cursor, Claude Desktop, OpenAI Responses, своё приложение) — используйте **Backend MCP server (раздел A)**. Раздел B нужен только тем, кто всё ещё дёргает `/api/v1/tools/kal/run`.

---

# A. Backend MCP server (ARG-023)

## A.1 Назначение

Backend MCP server (`backend/src/mcp/server.py`) — это process-internal фасад между MCP-совместимым LLM-клиентом и существующими сервисами ARGUS:

* `ScanService` (создание / статус / отмена сканов)
* `FindingsRepository` (выдача и пометка false-positive)
* `PolicyEngine` + `ScopeEngine` (pre-flight для tool calls)
* `ApprovalService` (запросы на approval для HIGH/DESTRUCTIVE действий)
* `ToolCatalog` + sandbox `ToolRunService` (ad-hoc запуски через approval-gate)
* `ReportService` (Midgard / Asgard / Valhalla — только enqueue + presigned URL)

Сервер **не** проксирует raw HTTP — он импортирует те же service-модули, что и FastAPI-приложение, поэтому tenant isolation, audit chain и policy guardrails работают единообразно. Сами артефакты (HTML/PDF, raw stdout/stderr) MCP-сервер **не передаёт по JSON-RPC** — клиент получает только presigned URL и SHA-256.

Реализация построена на **FastMCP** (официальный Python MCP SDK). Сервер поддерживает протокол MCP 2024-11-05 и две транспорт-схемы из спецификации:

* `stdio` — приоритетный для desktop / IDE клиентов (Cursor, Claude Desktop). Аутентификация падает обратно на `MCP_AUTH_TOKEN`.
* `streamable-http` — production-режим за reverse-proxy / OAuth-шлюзом. Bearer-токен / API-key обязательны.
* `sse` — устаревший transport MCP, поддерживается ради совместимости со старыми клиентами; новые интеграции должны использовать `streamable-http`.

---

## A.2 Запуск

### A.2.1 Stdio (рекомендуется для локальной разработки)

```powershell
# из корня репозитория
$env:MCP_AUTH_TOKEN = "dev-token"
python -m src.mcp.server
```

или явно:

```powershell
python -m src.mcp.server --transport stdio --log-level INFO
```

В stdio-режиме сервер не открывает сокетов; LLM-клиент сам спавнит процесс и общается через stdin/stdout. По умолчанию аутентификация необязательна (`MCP_REQUIRE_AUTH=false`), эффективный `tenant_id` берётся из `MCP_STDIO_TENANT_ID`.

### A.2.2 Streamable HTTP (production)

```powershell
$env:MCP_AUTH_TOKEN = "..."
python -m src.mcp.server `
  --transport streamable-http `
  --host 0.0.0.0 `
  --port 8765 `
  --log-level INFO
```

Доступ:

```text
POST  http://<host>:8765/mcp        — JSON-RPC body
GET   http://<host>:8765/mcp        — SSE stream (server → client notifications)
DELETE http://<host>:8765/mcp       — terminate session
```

В HTTP-режиме `MCP_REQUIRE_AUTH=true` (default), и сервер отклоняет вызовы без `Authorization: Bearer <token>` или `X-API-Key: <key>`.

### A.2.3 SSE (legacy)

```powershell
python -m src.mcp.server --transport sse --port 8765
```

Используется для совместимости с MCP-клиентами SDK ≤ 0.x. Новые интеграции — только `streamable-http`.

### A.2.4 Параметры CLI

| Флаг | Эквивалент env | Default | Назначение |
|------|----------------|---------|-----------|
| `--transport` | `MCP_TRANSPORT` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| `--host` | `MCP_HTTP_HOST` | `127.0.0.1` | Bind host для HTTP-транспортов |
| `--port` | `MCP_HTTP_PORT` | `8765` | Bind port для HTTP-транспортов |
| `--mount-path` | — | `null` | Опциональный prefix для SSE |
| `--log-level` | `MCP_LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` \| `CRITICAL` |

---

## A.3 Аутентификация

Сервер реализует три канала аутентификации, проверяемые по очереди (`backend/src/mcp/auth.py`):

1. **Static bearer token** — `Authorization: Bearer <MCP_AUTH_TOKEN>`. Сравнение через `hmac.compare_digest`. Метод записывается в audit как `static_token`.
2. **JWT bearer token** — `Authorization: Bearer <jwt>`. Декодируется тем же `_decode_jwt` (`src.core.auth`), что и FastAPI; принимается только `type=access` с непустыми `sub` и `tenant_id`. Метод: `jwt`.
3. **API key** — `X-API-Key: <key>`. Допускаются ключи из CSV-env `ARGUS_API_KEYS` (роль user) и значение `settings.admin_api_key` (роль admin, `is_admin=true`). Метод: `api_key`.

Если ни один канал не сработал и `MCP_REQUIRE_AUTH=true` — поднимается `AuthenticationError` (`mcp_auth_unauthenticated`, HTTP 401), call записывается в audit как DENIED.

Stdio-режим в режиме `MCP_REQUIRE_AUTH=false` (default) не требует токена и присваивает `MCPAuthContext(method="stdio_local", tenant_id=settings.mcp_stdio_tenant_id)`.

### A.3.1 Tenant isolation

Tenant-id берётся **исключительно** из аутентифицированного контекста (`MCPAuthContext.tenant_id`):

* Каждый tool / resource / prompt видит только один доверенный `tenant_id`.
* Если payload явно содержит `tenant_id` (например, `approvals.list(tenant_id=...)`) — он сверяется с аутентифицированным через `assert_tenant_match` (`backend/src/mcp/tenancy.py`); при несовпадении бросается `TenantMismatchError` (`mcp_tenant_mismatch`, HTTP 403).
* Заголовок `X-Tenant-ID` принимается только как narrowing-подсказка и игнорируется, если расходится с аутентифицированным.

Cross-tenant попытки логируются как `mcp.tenancy.cross_tenant_attempt` для последующего пост-мортем audit'а.

Тесты tenant isolation: `backend/tests/unit/mcp/test_tenancy.py`, `test_tenant_isolation.py`, и e2e в `backend/tests/integration/mcp/test_e2e_smoke.py`.

---

## A.4 Capability surface

### A.4.1 Tools (15)

Каждый tool принимает строго типизированный Pydantic `payload` и возвращает Pydantic-результат. Модели описаны в `backend/src/mcp/schemas/`.

#### Scans

| Tool | Input | Output | Описание |
|------|-------|--------|----------|
| `scan.create` | `ScanCreateInput` | `ScanCreateResult` | Enqueue нового скана. Profile `DEEP` требует `justification ≥ 10 chars` (иначе `mcp_approval_required`). |
| `scan.status` | `ScanStatusInput` | `ScanStatusResult` | Текущий статус, прогресс и severity-counts. |
| `scan.cancel` | `ScanCancelInput` | `ScanCancelResult` | Отмена; `reason` записывается в audit. |

#### Findings

| Tool | Input | Output | Описание |
|------|-------|--------|----------|
| `findings.list` | `FindingListInput` | `FindingListResult` | Пагинированный список с фильтрами `severity` / `cwe` / `owasp_category` / `confidence`. |
| `findings.get` | `FindingGetInput` | `FindingDetail` | Один finding (с redacted evidence + PoC). |
| `findings.mark_false_positive` | `FindingMarkFalsePositiveInput` | `FindingMarkResult` | Идемпотентно; повторный вызов возвращает `unchanged`. |

#### Approvals

| Tool | Input | Output | Описание |
|------|-------|--------|----------|
| `approvals.list` | `ApprovalListInput` | `ApprovalListResult` | Список approval-запросов (`pending` / `granted` / `denied` / `revoked` / `expired`). |
| `approvals.decide` | `ApprovalDecideInput` | `ApprovalDecideResult` | Запись решения. **GRANT требует Ed25519-подписи** — сервер только верифицирует, никогда не подписывает. |

#### Tool catalog & ad-hoc runs

| Tool | Input | Output | Описание |
|------|-------|--------|----------|
| `tool.catalog.list` | `ToolCatalogListInput` | `ToolCatalogListResult` | Снимок подписанного каталога (sandbox-internal поля `image` / `command_template` вырезаны). |
| `tool.run.trigger` | `ToolRunTriggerInput` | `ToolRunTriggerResult` | Запуск инструмента. **HIGH / DESTRUCTIVE never executed inline** — создаётся approval-запрос и возвращается `status=approval_pending`. |
| `tool.run.status` | `ToolRunStatusInput` | `ToolRunStatusResult` | Lifecycle-статус ad-hoc запуска. |

#### Reports

| Tool | Input | Output | Описание |
|------|-------|--------|----------|
| `report.generate` | `ReportGenerateInput` | `ReportGenerateResult` | Только enqueue; tier ∈ `MIDGARD` \| `ASGARD` \| `VALHALLA`, format ∈ `HTML` \| `PDF` \| `JSON` \| `CSV` \| `SARIF` \| `JUNIT`. |
| `report.download` | `ReportDownloadInput` | `ReportDownloadResult` | Возвращает короткоживущий presigned URL + SHA-256. **Байты артефакта НИКОГДА не идут через JSON-RPC.** |

#### Policy & scope

| Tool | Input | Output | Описание |
|------|-------|--------|----------|
| `scope.verify` | `ScopeVerifyInput` | `ScopeVerifyResult` | Проверка target против customer scope. По умолчанию default-deny. |
| `policy.evaluate` | `PolicyEvaluateInput` | `PolicyEvaluateResult` | PolicyEngine pre-flight: `allowed` / `requires_approval` / `denied`. Используется LLM перед `tool.run.trigger`. |

### A.4.2 Resources (4)

URIs в схеме `argus://...`. JSON-сериализация всегда детерминирована (`sort_keys=True, separators=(",",":")`).

| URI | Тип | Размер cap | Описание |
|-----|-----|------------|----------|
| `argus://catalog/tools` | concrete | 200 entries | Подписанный каталог инструментов (sandbox-internal поля убраны). |
| `argus://findings/{scan_id}` | template | 200 entries | Tenant-scoped findings одного скана; `scan_id` валидируется (8..64 chars). |
| `argus://reports/{report_id}` | template | — | Tenant-scoped метаданные отчёта + presigned URL (`format=JSON` по умолчанию). |
| `argus://approvals/pending` | concrete | 100 entries | Pending approval-запросы текущего тенанта. Операторы должны пуллить и решать через `approvals.decide`. |

### A.4.3 Prompts (3)

Шаблоны для LLM (никогда не вызывают сервер). Возвращают список `[AssistantMessage(system_guidance), UserMessage(rendered_block)]`.

| Prompt | Аргументы | Назначение |
|--------|-----------|------------|
| `vulnerability.explainer` | `title`, `severity`, `description?`, `cwe?`, `owasp_category?` | Объяснение finding'а нетехнической аудитории (3 параграфа). |
| `remediation.advisor` | `title`, `severity`, `stack?`, `evidence_summary?`, `cwe?` | Numbered list: primary fix → defense-in-depth → verification step. |
| `severity.normalizer` | `advisory_text`, `impact_hint?` | Маппинг свободного advisory на CRITICAL/HIGH/.../INFO + CVSS-3.1 vector + OWASP A01..A10. |

---

## A.5 Audit log format

Каждый tool/resource/prompt вызов проходит через `MCPAuditLogger` (`backend/src/mcp/audit_logger.py`) и попадает в общий hash-chain `AuditLogger` (тот же sink, что для FastAPI и sandbox).

### A.5.1 Поля события

| Поле | Тип | Описание |
|------|-----|----------|
| `event_type` | `AuditEventType` | `PREFLIGHT_PASS` для ALLOWED, `PREFLIGHT_DENY` для DENIED / ERROR. |
| `tenant_id` | UUID | Из `MCPAuthContext.tenant_id`. Никогда не из payload. |
| `scan_id` | UUID? | Если передан в `extra_payload` (например, для `scan.status`). |
| `actor_id` | UUID? | `MCPAuthContext.user_id` если это валидный UUID; иначе `null` + `payload.actor="mcp_client"`. |
| `decision_allowed` | bool | `True` для ALLOWED, иначе `False`. |
| `failure_summary` | string? | **Closed taxonomy** — например `mcp_auth_unauthenticated`, `mcp_tenant_mismatch`, `mcp_validation_error`, `mcp_internal_error`. Никогда не свободный текст. |
| `payload.actor` | string | Всегда `"mcp_client"` — позволяет отфильтровать MCP-трафик от HTTP/sandbox в одном sink'е. |
| `payload.tool_name` | string | Например `scan.create`, `tool.run.trigger`. |
| `payload.arguments_hash` | string | **SHA-256 hex** канонической JSON-сериализации payload'а (sort_keys, no whitespace). Сами аргументы НЕ сохраняются — клиенты могут передать токены / PII в свободных полях. |
| `payload.outcome` | string | `allowed` / `denied` / `error`. |
| `payload.<extra>` | mixed | Дополнительные структурированные поля из tool-специфичного `extra_audit_payload` (`scan_id`, `finding_id`, `tool_id`, `tier`, `format`, `decision`, …). |

### A.5.2 Закрытая таксономия `failure_summary`

| Code | HTTP | Когда |
|------|------|------|
| `mcp_auth_unauthenticated` | 401 | Bearer/API key отсутствует или отвергнут. |
| `mcp_auth_forbidden` | 403 | Auth прошла, но нет прав. |
| `mcp_tenant_mismatch` | 403 | Заявленный tenant не совпадает с аутентифицированным. |
| `mcp_scope_violation` | 403 | Target вне customer scope (default-deny). |
| `mcp_approval_required` | 403 | HIGH/DESTRUCTIVE действие без подписанного approval. |
| `mcp_policy_denied` | 403 | PolicyEngine явно запретил. |
| `mcp_resource_not_found` | 404 | Ресурс отсутствует или принадлежит другому тенанту (одинаковый ответ — anti-enumeration). |
| `mcp_validation_error` | 422 | Pydantic validation для аргументов. |
| `mcp_rate_limited` | 429 | Per-tool / per-tenant rate limit превышен. |
| `mcp_upstream_error` | 502 | Внутренний сервис ARGUS вернул необрабатываемую ошибку. |

Полный список — `backend/src/mcp/exceptions.py::_ALL_ERROR_CODES`.

### A.5.3 Echo audit_event_id обратно клиенту

Tools, чьи result-схемы содержат поле `audit_event_id`, получают его автоматически после успешного allow-emit. Это позволяет LLM показать оператору ссылку на запись audit'а без лишнего call'а к API.

### A.5.4 Пример события (JSON shape)

```json
{
  "event_id": "0d7d9e7e-7c1f-4a4e-9e6c-2a1f0b9c8d12",
  "event_type": "PREFLIGHT_PASS",
  "ts": "2026-04-19T12:34:56.789Z",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "scan_id": null,
  "actor_id": null,
  "decision_allowed": true,
  "failure_summary": null,
  "payload": {
    "actor": "mcp_client",
    "tool_name": "policy.evaluate",
    "arguments_hash": "9c4e7c6a3b1d4a8a8b1f5e9b6c2a1f0b9c8d12cafe...",
    "outcome": "allowed",
    "tool_id": "subfinder",
    "risk_level": "passive"
  }
}
```

---

## A.6 Закрытая таксономия ошибок (JSON-RPC)

FastMCP сериализует исключения в JSON-RPC error channel:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32000,
    "message": "[mcp_tenant_mismatch] Provided tenant_id does not match the authenticated tenant scope."
  }
}
```

`message` ВСЕГДА начинается с `[<code>] <human-safe summary>`. `<code>` — один из значений раздела A.5.2. Никогда не содержит SQL-фрагменты, stack frames, секреты или PII. Любая внутренняя `Exception`, не подпадающая под `MCPError`, конвертируется в `mcp_internal_error` ("An internal error occurred while executing the tool.") + ERROR-audit-событие; полный traceback пишется в server-side logger.

---

## A.7 Безопасность guardrails

| Guardrail | Реализация |
|-----------|------------|
| Default-deny scope | `scope.verify` без загруженной scope-конфигурации возвращает `allowed=false`. |
| Approval-gating HIGH/DESTRUCTIVE | `tool.run.trigger` возвращает `status=approval_pending` и НИКОГДА не запускает HIGH/DESTRUCTIVE инлайном. Запуск только после `approvals.decide(decision=GRANT)` с валидной Ed25519-подписью. |
| Tenant isolation | Каждый payload `tenant_id` валидируется через `assert_tenant_match`; ресурсы с `resource_tenant_id ≠ auth.tenant_id` отвергаются как `mcp_resource_not_found` (anti-enumeration). |
| Аргументы не сохраняются | В audit пишется только SHA-256 канонической JSON. Размер input для хеша ограничен 64 KiB (overflow обрезается). |
| No artifact bytes via JSON-RPC | Reports / raw outputs возвращаются как presigned URL + SHA-256; LLM-клиент сам качает с MinIO. |
| Pydantic strict mode | Все input-схемы используют `extra="forbid"`, `frozen=True` и strict-типы. |
| `report.generate` валидация | `scan_id` < 8 chars и любой неизвестный tier/format отвергаются на schema-уровне с `mcp_validation_error`. |
| Pagination cap | `PaginationInput.limit ≤ 200` — клиент не может выкачать всё одним вызовом. |
| Audit emit failure-isolation | Если запись в audit не удалась, MCP call всё равно завершается; ошибка пишется в server logger как `mcp.audit.*_emit_failed` (не блокирует ответ клиенту). |

---

## A.8 Конфигурация (env-переменные)

Все переменные ниже валидируются `Settings` (`backend/src/core/config.py`).

| Переменная | Default | Описание |
|------------|---------|----------|
| `MCP_TRANSPORT` | `stdio` | `stdio` \| `streamable-http` \| `sse`. |
| `MCP_HTTP_HOST` | `127.0.0.1` | Bind host для HTTP-транспортов. |
| `MCP_HTTP_PORT` | `8765` | Bind port (1..65535). |
| `MCP_SERVER_NAME` | `argus` | Возвращается клиенту в `initialize.serverInfo.name`. |
| `MCP_LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` \| `CRITICAL`. |
| `MCP_AUTH_TOKEN` | — | Static bearer token. **Обязателен для HTTP**, опционален для stdio. |
| `MCP_REQUIRE_AUTH` | — | `true` принудительно требует auth даже в stdio; `false` отключает требование в HTTP (тестовый режим). |
| `MCP_STDIO_TENANT_ID` | `00000000-...-000000000001` | Default tenant для stdio без токена. |
| `MCP_STDIO_ACTOR_ID` | `local-stdio` | `MCPAuthContext.user_id` для stdio без токена. |
| `MCP_CONFIG_PATH` | `backend/config/mcp/server.yaml` | Подписанный server-config (caps, rate limits, key registry). |
| `MCP_CONFIG_SIGNATURES_PATH` | `backend/config/mcp/SIGNATURES` | Файл с PGP/Ed25519-подписями server-config. |
| `MCP_CONFIG_KEYS_DIR` | `backend/config/mcp/_keys` | Каталог с публичными ключами для верификации. |
| `ARGUS_API_KEYS` | — | CSV из user-роль API ключей (плюс отдельный `ADMIN_API_KEY` из общего settings). |
| `X-Tenant-ID` (header) | — | Narrowing-подсказка; принимается только если совпадает с auth-tenant. |

### A.8.1 Notifications (ARG-035) — Slack / Linear / Jira webhooks

Под-система выключена по умолчанию (`MCP_NOTIFICATIONS_ENABLED=false`). Включение делает один общий kill-switch + отдельный `enabled` флаг в `server.yaml` для каждого адаптера. Все секреты — **только** через env, никогда из конфига:

| Переменная | Назначение |
|------------|------------|
| `MCP_NOTIFICATIONS_ENABLED` | Master switch (`true`/`false`). По умолчанию `false`. |
| `SLACK_WEBHOOK_URL` | Slack incoming-webhook URL. |
| `LINEAR_API_KEY` | Linear personal/integration API key. |
| `LINEAR_API_URL` | Override Linear GraphQL endpoint (test/staging). Default `https://api.linear.app/graphql`. |
| `LINEAR_TEAM_MAP` | JSON `{"<tenant_id>": "<team_id>"}` для маппинга tenant → team. |
| `LINEAR_DEFAULT_TEAM_ID` | Fallback team если tenant не в `LINEAR_TEAM_MAP`. |
| `JIRA_SITE_URL` | Базовый URL Jira Cloud (`https://<site>.atlassian.net`). |
| `JIRA_USER_EMAIL` | Email пользователя для HTTP Basic. |
| `JIRA_API_TOKEN` | Atlassian Cloud API token. |
| `JIRA_PROJECT_KEY` | Ключ проекта (например `SEC`). |
| `JIRA_FINDING_FIELD_ID` | Custom field id для traceability. Default `customfield_10042`. |
| `JIRA_ISSUE_TYPE_NAME` | Тип issue. Default `Bug`. |
| `JIRA_PRIORITY_MAP` | JSON map `{"critical":"Highest", ...}` для нестандартных priority schemes. |
| `MCP_NOTIFICATIONS_HTTP_TIMEOUT_SECONDS` | HTTP timeout per attempt. Default `10.0`. |
| `MCP_NOTIFICATIONS_MAX_ATTEMPTS` | Retry attempts per dispatch. Default `3` (1s/4s/16s jittered). |

`server.yaml` (проверяется Ed25519-подписью!) описывает поведение — какие events / severities ловит каждый адаптер, какие тенанты опт-аут, и параметры circuit-breaker / retry. Минимальный пример:

```yaml
notifications:
  enabled: false        # глобальный kill-switch (env MCP_NOTIFICATIONS_ENABLED имеет приоритет)
  adapters:
    slack:
      enabled: false
      events: [approval.pending, scan.completed, critical.finding.detected]
      severities: [critical, high, medium]
      env_secrets: [SLACK_WEBHOOK_URL]   # документация
    linear:
      enabled: false
      events: [critical.finding.detected]
      severities: [critical, high]
      env_secrets: [LINEAR_API_KEY, LINEAR_TEAM_MAP]
    jira:
      enabled: false
      events: [critical.finding.detected]
      severities: [critical, high]
      env_secrets: [JIRA_SITE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY]
  per_tenant_disabled_adapters: {}
  retry:
    max_attempts: 3
    base_seconds: 1.0
    factor: 4.0          # → 1s / 4s / 16s; full-jitter применяется поверх
  circuit_breaker:
    failure_threshold: 5
    cooldown_seconds: 60
```

**Контракт adapter-результата.** Каждый адаптер возвращает `AdapterResult`. Поле `target_redacted` — это `sha256(URL)[:12]`; в логах / audit нигде не встречается ни URL, ни токен. На сбое `error_code` = closed-taxonomy (`http_4xx`, `http_5xx`, `network_error`, `timeout`, `circuit_open`, …). Skip-сценарии (`disabled`, `missing_secret`, `severity_not_routed`, `idempotent_duplicate`) идут через `skipped_reason` без `error_code`.

**Idempotency.** Adapter-base держит per-(adapter × tenant) bounded-LRU set (1024 событий) на `event_id`. Linear / Jira дополнительно записывают `finding.root_cause_hash` в `externalId` / `customfield_argus_finding_id` — оператор может де-дуплицировать в самой системе.

**Circuit breaker.** На пятом подряд сбое для `(adapter × tenant)` пары breaker открывается на 60 секунд; в логе пишется `mcp.notifications.circuit_open` (warning). Все последующие dispatch-вызовы в этой комбинации возвращают `skipped_reason=circuit_open` без HTTP-call'а до истечения cooldown.

#### Slack interactive callbacks (ARG-048)

ARG-035 шлёт в Slack кнопки **Approve** / **Deny** для событий типа `approval.pending`. ARG-048 закрывает обратный канал: входящий FastAPI router принимает Slack action callback, проверяет HMAC-SHA-256 подпись, валидирует replay-window, и пишет soft-intent запись в неизменяемый audit-log. **Финальное криптографическое одобрение по-прежнему требует Ed25519-подпись через `ApprovalService.verify`** — клик в Slack ≠ destructive action; он лишь фиксирует намерение оператора.

Endpoint: `POST /api/v1/mcp/notifications/slack/callback`

| Переменная | Назначение |
|------------|------------|
| `SLACK_SIGNING_SECRET` | Slack App → *Basic Information* → *Signing Secret*. Без неё router отвечает HTTP 503 на каждый запрос (hard-fail mode — **не молча пропускаем неподписанные коллбеки**). |

Slack App configuration:
1. Slack App → *Interactivity & Shortcuts* → включить *Interactivity*.
2. *Request URL* → `https://<argus-host>/api/v1/mcp/notifications/slack/callback`.
3. *Basic Information* → скопировать *Signing Secret* в env-var `SLACK_SIGNING_SECRET`.

**Контракт коллбека (security gates, в порядке проверки):**

1. `SLACK_SIGNING_SECRET` обязан быть выставлен → иначе HTTP 503.
2. `X-Slack-Signature` и `X-Slack-Request-Timestamp` headers обязательны → иначе HTTP 401.
3. Body cap: 16 KiB (`MAX_BODY_BYTES`) → иначе HTTP 413.
4. Timestamp в окне ±5 минут (`REPLAY_WINDOW_SECONDS = 300`); past и future одинаково → иначе HTTP 401 `stale_timestamp`.
5. Подпись `v0=<HMAC-SHA-256 hexdigest>` вычисляется над `b"v0:" + timestamp + b":" + raw_body`; сравнение через `hmac.compare_digest` (constant-time) → mismatch HTTP 401 `invalid_signature`.
6. Body — `application/x-www-form-urlencoded` поле `payload=<json>`; `payload.type == "block_actions"` обязательно (другие типы → HTTP 422 `unsupported_payload_type`).
7. `payload.actions[0].action_id` имеет формат `approve::<approval_id>` либо `deny::<approval_id>` (соответствует тому, что эмитит `build_slack_payload` из ARG-035). `approval_id` ≤ 128 символов → иначе HTTP 422.

**Audit-trail.** На успех router пишет в `AuditLogger` событие типа `APPROVAL_REQUESTED` со следующими полями:

| Поле | Значение |
|------|----------|
| `event_type` | `approval.requested` |
| `tenant_id` | `00000000-0000-0000-0000-000000000000` (Slack soft-intent partition; не путать с реальными tenant_id) |
| `decision_allowed` | `true` для `approve`, `false` для `deny` |
| `failure_summary` | `null` для approve; `"slack_denied"` для deny |
| `payload.action` | `"approve"` либо `"deny"` |
| `payload.approval_id` | extracted из action_id (truncated to 64 chars) |
| `payload.slack_user_id` | `payload.user.id` из Slack body (truncated to 64 chars; `"unknown"` если отсутствует) |
| `payload.source` | всегда `"slack"` |

Audit-цепочка хеш-связана и проверяется `AuditLogger.verify_chain(tenant_id=...)`; повредить запись post-hoc нельзя.

**Signing-secret rotation.** Slack поддерживает hot-rotation: создайте новый App secret, обновите env-var, перезапустите backend (lifespan-перезагрузка читает `settings.slack_signing_secret` ленивым образом). Replay-окно 5 минут означает, что после рестарта старые in-flight запросы провалятся с `invalid_signature` — это by design.

**Тестовое покрытие.** ~36 тестов в трёх файлах:

* `backend/tests/unit/api/routers/test_mcp_slack_callbacks.py` — pure-function + endpoint contract (~21 кейс).
* `backend/tests/integration/mcp/test_slack_interactive_flow.py` — producer→consumer parity, audit-цепочка для нескольких approvals (~7 кейсов).
* `backend/tests/security/test_slack_callback_signature_replay_protection.py` — adversary model: replay, signature tampering, body smuggling, hard-fail (~16 кейсов).

### A.8.2 Rate limiter (ARG-035) — token bucket per client × per tenant

Каждый `tools/call` проходит через `TokenBucketLimiter.acquire(client_id, tenant_id, tokens=1)` ДО запуска tool body. Пропускает только если **обе** корзины (client + tenant) имеют ≥1 токен. На отказ возвращается JSON-RPC error с `code=-32029` и `data.retry_after` (секунды до следующего токена в дефицитной корзине) + `data.scope` = `"client" | "tenant"`.

Backend выбирается через `server.yaml`:

```yaml
rate_limiter:
  backend: memory                       # memory | redis
  redis_key_prefix: argus:mcp:rl
  default_client_budget: { rate_per_second: 5, burst: 30 }
  default_tenant_budget: { rate_per_second: 50, burst: 300 }
  per_client_budgets: {}                # optional override map
  per_tenant_budgets: {}                # optional override map
```

* **`memory`** — `InMemoryTokenBucket`, single-process, asyncio-aware. Используется по умолчанию (zero-deps).
* **`redis`** — `RedisTokenBucket`, distributed; refill+decrement выполняется атомарно внутри Redis Lua-скрипта (`EVALSHA` cached). Требует тот же Redis URL, что и Celery broker. Если Redis недоступен — limiter logs `mcp.rate_limiter.redis_unavailable` и fails open (per-call) для не блокирования продакшен-трафика; алерты должны быть на этот лог-record.

**Operator runbook.** При превышении лимита клиент получает:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32029,
    "message": "Rate limit exceeded for tenant; retry after 1.83s",
    "data": { "retry_after": 1.83, "scope": "tenant" }
  }
}
```

LLM-клиент обязан подождать `retry_after` секунд + jitter и повторить вызов. Полный гид по budget-tuning — в `ai_docs/develop/reports/2026-04-19-arg-035-mcp-webhooks-rate-limiter-report.md`.

---

## A.9 Интеграция с LLM-клиентом

### A.9.1 Cursor / Claude Desktop (stdio)

В `mcp.json` хоста:

```json
{
  "mcpServers": {
    "argus": {
      "command": "python",
      "args": ["-m", "src.mcp.server"],
      "cwd": "D:/Developer/Pentest_test/ARGUS/backend",
      "env": {
        "MCP_AUTH_TOKEN": "dev-token",
        "MCP_STDIO_TENANT_ID": "00000000-0000-0000-0000-000000000001"
      }
    }
  }
}
```

### A.9.2 OpenAI Responses / streaming HTTP клиенты

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client(
    "https://argus.example.com/mcp",
    headers={"Authorization": "Bearer <jwt>"},
) as (read, write, get_session_id):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        result = await session.call_tool(
            "policy.evaluate",
            {"payload": {"tool_id": "subfinder", "target": "https://example.com", "risk_level": "passive"}},
        )
```

### A.9.3 Типичный flow LLM-агента

1. `initialize` → читаем `tools[]` / `resources[]` / `prompts[]`.
2. `policy.evaluate(tool_id, target, risk_level)` → `allowed` / `requires_approval` / `denied`.
3. Если `requires_approval` — `approvals.list(status=pending)` + ждём `approvals.decide(GRANT, signature, public_key_id)`.
4. `tool.run.trigger(tool_id, target, params)` → возвращает `tool_run_id`.
5. Polling `tool.run.status(tool_run_id)` до терминального состояния.
6. `findings.list(scan_id)` → `findings.get(finding_id)` → опционально `prompts/get(vulnerability.explainer, ...)` для рендера ответа оператору.
7. `report.generate(scan_id, tier, format)` → `report.download(report_id)` → отдаём presigned URL.

---

## A.10 Тесты

| Слой | Файлы | Покрывает |
|------|-------|-----------|
| Unit | `backend/tests/unit/mcp/test_*.py` (≥ 80 кейсов) | Tools per-domain, resources, prompts, auth каналы, tenant isolation, audit emission, schemas validation, service helpers. |
| Integration | `backend/tests/integration/mcp/test_e2e_smoke.py` | In-process `build_app()` → capability surface + tool calls + tenant isolation + audit drain. |
| Integration (stdio) | `backend/tests/integration/mcp/test_stdio_smoke.py` | Реальный subprocess `python -m src.mcp.server` с MCP-клиентом по stdio. |
| Integration (HTTP) | `backend/tests/integration/mcp/test_http_smoke.py` | Subprocess в `streamable-http` режиме на свободном порту с MCP-клиентом по `streamablehttp_client`. |
| Docstring gate (ARG-039) | `backend/tests/test_mcp_tools_have_docstrings.py` | Каждый публичный MCP tool/resource/template/prompt содержит `description` ≥ 30 символов. |
| OpenAPI snapshot (ARG-039) | `backend/tests/integration/mcp/test_openapi_export_stable.py` | Снэпшот спецификации, покрытие всех зарегистрированных entity, валидность всех `$ref` против `components.schemas`. |
| Notifications unit (ARG-035) | `backend/tests/unit/mcp/services/notifications/test_*.py` | Per-adapter (slack/linear/jira) payload + retry + circuit + dedup + secret hygiene; dispatcher fan-out / disable-paths / env-flag. |
| Rate limiter unit (ARG-035) | `backend/tests/unit/mcp/runtime/test_rate_limiter.py` | `BucketBudget` validation, `InMemoryTokenBucket` refill/concurrency/burst, `RedisTokenBucket` Lua interaction (mocked Redis), factory dispatch. |
| Notifications integration (ARG-035) | `backend/tests/integration/mcp/test_notifications_dispatch.py` | End-to-end dispatch через все три адаптера c `httpx.MockTransport`; partial failure isolation, idempotency, per-tenant opt-out. |
| Rate limiter integration (ARG-035) | `backend/tests/integration/mcp/test_rate_limiter_under_load.py` | 500 concurrent acquires, JSON-RPC `-32029` контракт, refill progression, per-tenant fairness. |
| Security gate (ARG-035) | `backend/tests/security/test_mcp_notification_no_secret_leak.py` | Webhook URL / Linear key / Jira token / generic patterns не появляются в `AdapterResult` или audit-log записи. |

Запуск:

```powershell
# unit only
python -m pytest tests/unit/mcp -q

# integration (~2 минуты — поднимает реальные subprocess)
python -m pytest tests/integration/mcp -q

# ARG-039 — гейты OpenAPI/SDK
python -m pytest tests/test_mcp_tools_have_docstrings.py tests/integration/mcp/test_openapi_export_stable.py -q
```

---

## A.11 OpenAPI 3.1 export + TypeScript SDK (ARG-039)

Помимо MCP wire-протокола, тот же набор tools/resources/prompts экспонируется как **OpenAPI 3.1** для интеграций, не использующих MCP клиент-сессию (внутренние UI, генераторы тестов, сторонние интеграторы).

### A.11.1 Контракт и mapping

Файл-источник правды: **`docs/mcp-server-openapi.yaml`** (committed, regenerated в CI).

| MCP entity | OpenAPI path | Метод | `operationId` | Тег |
|------------|-------------|-------|---------------|-----|
| `@mcp.tool(name="x.y")` | `POST /rpc/x.y` | POST | `call_x_y` | `mcp-tool` |
| `@mcp.resource("argus://x/y")` | `GET /resources/x/y` | GET | `read_argus_x_y` | `mcp-resource` |
| Resource template `argus://x/{id}` | `GET /resources/x/{id}` | GET (path param) | `read_argus_x` | `mcp-resource` |
| `@mcp.prompt(name="x.y")` | `POST /prompts/x.y` | POST | `render_x_y` | `mcp-prompt` |

Pydantic-схемы поднимаются из локальных `$defs` в глобальный `components.schemas`; все `$ref` переписываются на `#/components/schemas/<Name>`. Спецификация — самодостаточный документ, валидный для `openapi-typescript-codegen`, `swagger-cli validate`, Redocly и любого совместимого инструментария.

`securitySchemes`: `bearer` (JWT / static / HMAC, см. `backend/src/mcp/auth.py`) и `apiKey` (`X-API-Key` из `ARGUS_API_KEYS` / `ADMIN_API_KEY`).

### A.11.2 Регенерация спецификации

Инвариант: спецификация — **детерминированный** артефакт, выходящий байт-в-байт одинаковым при тех же исходниках (списки сортированы по ключу, YAML дампится с `sort_keys=True`).

```powershell
# из backend/
python -m scripts.export_mcp_openapi --out ../docs/mcp-server-openapi.yaml

# CI-режим (exit 1 при дрейфе): используется в job `mcp-openapi-drift`
python -m scripts.export_mcp_openapi --check
```

После любого изменения tools/resources/prompts (новый параметр, новая модель, изменение описания) — обязательно перегенерируйте спецификацию и закоммитьте обновлённый `docs/mcp-server-openapi.yaml` вместе с кодом.

### A.11.3 TypeScript SDK

Сгенерированный клиент: **`Frontend/src/sdk/argus-mcp/`** (commited). Состав:

* `core/` — runtime: `OpenAPI`, `request`, `CancelablePromise`, `ApiError`.
* `models/` — TypeScript интерфейсы для каждой Pydantic-модели.
* `services/` — `McpToolService`, `McpResourceService`, `McpPromptService` со статическими методами для каждого `operationId`.

Регенерация:

```powershell
cd Frontend
npm install                 # если ещё не делали
npm run sdk:generate        # перезаписывает src/sdk/argus-mcp/
npm run sdk:check           # генерация + git diff --exit-code (CI-режим)
```

Использование:

```typescript
import { OpenAPI, McpToolService } from "@/sdk/argus-mcp";

OpenAPI.BASE = "https://argus.example.com/mcp";
OpenAPI.TOKEN = async () => getJwt();

const result = await McpToolService.callScanCreate({
  requestBody: {
    payload: {
      scope: { domains: ["example.com"] },
      profile: "QUICK",
    },
  },
});
```

### A.11.4 CI-гейты

| Job | Step | Что проверяет | Сбой говорит о |
|-----|------|---------------|----------------|
| `mcp-openapi-drift` | `python -m scripts.export_mcp_openapi --check` | `docs/mcp-server-openapi.yaml` совпадает с regenerated | Изменили MCP entity → не перегенерили спецификацию |
| `mcp-openapi-drift` | `pytest tests/test_mcp_tools_have_docstrings.py` | Каждый tool/resource/prompt описан строкой ≥ 30 символов | Новый entity без полноценного `description` |
| `mcp-openapi-drift` | `npm run sdk:check` | `Frontend/src/sdk/argus-mcp/` совпадает с regenerated | Спецификация обновлена → SDK не перегенерирован |

Все три падают exit 1 — пайплайн `build` не запускается без зелёного `mcp-openapi-drift`.

### A.11.5 Pinned-версии инструментов

* `openapi-typescript-codegen@0.29.0` — pinned exact в `Frontend/package.json` (без `^`/`~`); SDK воспроизводимо собирается.
* Python: `pyyaml`, `mcp` — версии из `backend/requirements.txt`.

---

# B. Legacy KAL MCP & `POST /api/v1/tools/kal/run`

> Раздел оставлен для обратной совместимости. Новые интеграции должны использовать **Backend MCP server (раздел A)**.

**Code:** `mcp-server/argus_mcp.py`, `backend/src/api/routers/tools.py`, `backend/src/recon/mcp/policy.py`, `backend/src/recon/mcp/kal_executor.py`

## B.1 Назначение

Отдельный процесс **MCP** (FastMCP) проксирует вызовы в HTTP API бэкенда. Для категорийных Kali-запусков используется единая точка **`POST /api/v1/tools/kal/run`** (KAL-002): argv проходит fail-closed политику, выполнение — в песочнице при **`SANDBOX_ENABLED=true`**, опционально выгрузка stdout/stderr в MinIO.

**Аутентификация клиента к API:** заголовок `Authorization: Bearer <ARGUS_API_KEY>` (если задан `ARGUS_API_KEY`). Тенант: `X-Tenant-ID` из env `ARGUS_TENANT_ID` или явно в теле KAL-запроса.

## B.2 HTTP: `POST /api/v1/tools/kal/run`

**Rate limit:** по IP, ключ `kal_run:<client_ip>` (см. router `tools`).

### B.2.1 Тело запроса (`KalRunRequest`)

| Поле | Тип | Обязательно | Описание |
|------|-----|---------------|----------|
| `category` | string | да | Категория политики (ниже); нормализация: lower-case, `-` → `_` |
| `argv` | string[] | да | 1…64 аргументов, каждый ≤ 4096 символов; **без shell** — список передаётся в exec |
| `target` | string | да | Цель для guardrails (host/URL); 1…2048 |
| `tenant_id` | string | нет | Для MinIO raw: `{tenant}/{scan}/recon/raw/...` |
| `scan_id` | string | нет | В паре с `tenant_id` включает загрузку артефактов |
| `password_audit_opt_in` | bool | нет | Для **hydra/medusa**: клиентский opt-in (плюс серверный `KAL_ALLOW_PASSWORD_AUDIT`) |

### B.2.2 Ответ (успех / отказ политики / валидация)

Типовые поля:

| Поле | Описание |
|------|----------|
| `success` | Успех выполнения процесса |
| `stdout`, `stderr` | Вывод инструмента |
| `return_code` | Код завершения |
| `execution_time` | Длительность (сек) |
| `policy_reason` | При отказе: например `unknown_category`, `tool_not_allowed_for_category`, `password_audit_opt_in_required`, `argv_injection_pattern`, `target_validation_failed`; при успехе часто `null` |
| `minio_keys` | Ключи загруженных объектов (если заданы `tenant_id` и `scan_id`) |

Политика **`kal_mcp_gated_tools_v1`** (`KAL_MCP_POLICY_ID` в коде).

## B.3 Категории политики KAL (`KAL_OPERATION_CATEGORIES`)

Разрешённый **первый** элемент `argv` (бинарник) для категории:

| Категория | Разрешённые бинарники | Примечания |
|-----------|----------------------|------------|
| `network_scanning` | `nmap`, `rustscan`, `masscan` | Цикл recon nmap завязан на эту категорию |
| `web_fingerprinting` | `httpx`, `whatweb`, `wpscan`, `nikto` | |
| `api_testing` | `httpx`, `nuclei`, `curl` | Удобно вызывать через **`run_tool`** с `argv_json` |
| `bruteforce_testing` | `gobuster`, `feroxbuster`, `dirsearch`, `ffuf`, `wfuzz`, `dirb` | Не **hydra** — см. `password_audit` |
| `ssl_analysis` | `openssl`, `testssl.sh` | Для `openssl` только подкоманды: `s_client`, `s_time`, `version`, `ciphers` |
| `dns_enumeration` | `dig`, `subfinder`, `amass`, `dnsx`, `host`, `nslookup`, `dnsrecon`, `fierce` | Для **amass** только подкоманда `enum` |
| `password_audit` | `hydra`, `medusa` | Нужны **`password_audit_opt_in=true`** и **`KAL_ALLOW_PASSWORD_AUDIT=true`** на сервере |
| `vuln_intel` | `searchsploit` | Разведка/intel по argv |

В argv запрещены шаблоны внедрения shell-метасимволов (см. `kal_argv_has_injection_risk`).

## B.4 Инструменты Legacy MCP (KAL-002)

Регистрируются в **`_register_kal_mcp_tools`**. Все ниже вызывают тот же **`kal_run`** → `POST /api/v1/tools/kal/run`.

### B.4.1 `run_network_scan`

- **Категория:** `network_scanning`
- **Параметры:** `tenant_id`, `scan_id`, `target`, `tool` (`nmap` \| `rustscan` \| `masscan`), `extra_args` (строка, парсится `shlex.split`)
- **Поведение:** для `nmap` argv = `["nmap", *extras, target]`; для `masscan` при пустых extras добавляется `-p 1-1000 --rate 1000`

### B.4.2 `run_web_scan`

- **Категория:** `web_fingerprinting`
- **Инструменты:** `httpx` (по умолчанию `-u target`, при необходимости `-silent`), `whatweb`, `wpscan`, `nikto`

### B.4.3 `run_ssl_test`

- **Категория:** `ssl_analysis`
- **Реализация:** только **`openssl s_client`** (+ `-servername`, `-connect host:port`); порт по умолчанию `443`, из URL извлекается хост/порт
- **testssl.sh:** через **`run_tool`** с `category=ssl_analysis` и `argv_json`, например `["testssl.sh", "--openssl", "/usr/bin/openssl", "https://host"]` (уточняйте флаги под образ sandbox)

### B.4.4 `run_dns_enum`

- **Категория:** `dns_enumeration`
- **Инструменты:** `dig`, `subfinder`, `amass`, `dnsx`, `host`, `nslookup` (обёртки с типовыми флагами)
- **dnsrecon / fierce:** в политике сервера разрешены, но отдельных MCP-обёрток нет — используйте **`run_tool`**

### B.4.5 `run_bruteforce`

- **Категория:** `bruteforce_testing`
- **Инструменты:** `gobuster`, `feroxbuster`, `dirsearch`, `ffuf`, `wfuzz`, `dirb` с дефолтным wordlist `/usr/share/wordlists/dirb/common.txt` в argv

### B.4.6 `run_tool`

- **Универсальный вызов:** `category`, `tenant_id`, `scan_id`, `target`, **`argv_json`** (JSON-массив строк), опционально `password_audit_opt_in`
- Используйте для **api_testing**, **vuln_intel**, **testssl.sh**, **dnsrecon**/**fierce**, кастомных безопасных argv в рамках категории

## B.5 Прочие Legacy MCP-инструменты (контекст)

- **Реестр Kali (`kali_*`):** вызовы унаследованных эндпоинтов `run_tool` по имени инструмента (не путать с KAL category API).
- **`va_enqueue_sandbox_scanner`:** очередь Celery для VA (dalfox, xsstrike, …) через `POST /api/v1/internal/va-tools/enqueue`, может требовать **`ARGUS_ADMIN_KEY`**.

---

## Связанные документы

- [deployment.md](./deployment.md) — `SANDBOX_ENABLED`, `SANDBOX_PROFILE`, `KAL_ALLOW_PASSWORD_AUDIT`, NMAP-флаги
- [scan-state-machine.md](./scan-state-machine.md) — цикл nmap, DNS recon, VA whatweb/nikto/feroxbuster/testssl, флаги searchsploit/trivy/HIBP
- [security-model.md](./security-model.md) — общая модель угроз, audit chain, scope engine
- [auth-flow.md](./auth-flow.md) — JWT, RBAC, CSRF — общие с MCP HTTP transport
