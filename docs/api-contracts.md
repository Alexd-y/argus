# ARGUS API Contracts

**Источник истины:** ARGUS/Frontend (и test/pentagi/frontend как референс).  
**Правило:** Backend реализуется строго по этим контрактам.

---

## 1. REST API (ARGUS Scanner)

Base URL: `/api/v1` (или `NEXT_PUBLIC_API_URL`)

### 1.1 Сканирование

Старый `POST /scans` (`target` + `email` + `options`) **без изменений**. Новые поля — только optional / additive.

`execution_mode` — immutable профиль исполнения (`production` \| `lab_unrestricted` \| `quick`).  
`scan_mode` / `options.scanType` — **глубина** скана, не режим исполнения.  
`ScanProfile.QUICK` в MCP = глубина, не Quick execution mode.

Канонический coverage-путь: **`GET /scans/{id}/coverage`** (существующий; не дублировать).  
Отчёт скана: существующий `GET /scans/{id}/report` (alias к reports pipeline), не второй генератор.

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `POST /scans` | POST | `{ target: string, email: string, options: ScanOptions, execution_mode?: ExecutionMode, scan_mode?: ScanDepth, quick?: QuickCreateOptions }` | `{ scan_id: string, status: string, message?: string }` | `{ error: string, code?: string, details?: object }` |
| `GET /scans/:id` | GET | — | `{ id: string, status: string, progress: number, phase: string, target: string, created_at: string, deadline_at?: string, quick_profile?: string, budget?: QuickBudgetView, stage?: string, execution_mode?: ExecutionMode }` | `{ error: string, code?: string }` |
| `POST /scans/:id/cancel` | POST | — | `{ scan_id: string, status: string, message?: string }` | `{ error: string, code?: string }` |
| `GET /scans/:id/plan` | GET | — | `QuickScanPlanView` (только `execution_mode=quick`) | 404 `{ error: string, code: "plan_not_applicable" }` для non-quick; 404 scan not found |
| `GET /scans/:id/coverage` | GET | — | `{ scan_id: string, requirements: object[], results: CoverageResult[] }` — `results[].reason_code` additive | `{ error: string, code?: string }` |
| `GET /scans/:id/findings` | GET | Query: `?severity&validated_only` | `Finding[]` | `{ error: string, code?: string }` |
| `GET /scans/:id/report` | GET | Query: `?format&tier` | Binary/stream или 404 `report_not_found` (generate via existing reports API) | `{ error: string, code?: string }` |
| `GET /scans/:id/events` | GET (SSE) | — | SSE stream: `{ event: string, phase?: string, progress?: number, message?: string, data?: object }` | — |
| `GET /quick/profiles` | GET | — | `{ profiles: QuickProfileCatalogItem[] }` | `{ error: string, code?: string }` |

**ExecutionMode:** `"production" | "lab_unrestricted" | "quick"`. Omit / null → `production` (backward compatible).

**QuickCreateOptions** (игнорируется, если `execution_mode` не `quick`):

```ts
{
  profile?: "compact" | "balanced" | "extended";  // default balanced
  severity_floor?: "critical" | "high" | "medium" | "low" | "info";
  enable_ai?: boolean;
  enable_oast?: boolean;
  enable_headless_on_signal?: boolean;
  wall_clock_budget_seconds?: number;
  ai_budget_seconds?: number;
  authenticated_context_id?: string;  // secret-store ref only; never a credential
  cloud_llm_allowed?: boolean;        // default false; clamped fail-closed
}
```

**QuickBudgetView / GET detail (optional, только quick):**

```ts
{
  wall_clock_budget_seconds: number;
  discovery_budget_seconds?: number;
  fingerprint_budget_seconds?: number;
  verification_budget_seconds?: number;
  ai_budget_seconds?: number;
  report_budget_seconds?: number;
  request_budget?: number;
  per_host_budget?: number;
  concurrency_budget?: number;
  reserve_for_validation_percent?: number;
}
```

**QuickScanPlanView** (`GET /scans/:id/plan`):

```ts
{
  scan_id: string;
  mode: "quick";
  profile: "compact" | "balanced" | "extended";
  plan_version: number;
  deadline_at: string;  // ISO-8601 Z
  budget: QuickBudgetView;
  stages: string[];
  tasks: object[];      // typed tool_id / capability_id; never argv/command
  fallbacks: string[];
  coverage_intent: Array<{ capability_id: string; reason_code: string; state?: string }>;
  assumptions: string[];
  prompt_version?: string;
  model_route?: string;
}
```

**CoverageResult** (существующий DTO, QUICK-007 расширяет `reason_code`):

```ts
{
  requirement_id: string;
  scan_id: string;
  asset_id: string;
  capability_id: string;
  status: string;  // CoverageStatus enum
  reason_code?: string | null;
  // examples: executed | budget_partial | fingerprint_mismatch
  //           | not_scheduled_by_quick_profile | deadline_reached | tool_error
  template_ids?: string[];
  evidence_ids?: string[];
  finding_id?: string | null;
  execution_evidence_id?: string | null;
}
```

Отсутствие finding ≠ coverage.

**QuickProfileCatalogItem** (`GET /quick/profiles`):

```ts
{
  name: "compact" | "balanced" | "extended";
  wall_clock_budget_seconds: number;
  ai_budget_seconds: number;
  reserve_for_validation_percent: number;
  max_targets: number;
  max_urls_per_host: number;
  crawl_depth: number;
  severity_floor: string;
  enable_ai: boolean;
  enable_oast: boolean;
  enable_headless_on_signal: boolean;
  request_budget: number;
  per_host_budget: number;
  concurrency_budget: number;
}
```

**Error codes (400/404):**

| code | HTTP | Когда |
|------|------|--------|
| `quick_mode_disabled` | 400 | `execution_mode=quick` при `ARGUS_QUICK_MODE_ENABLED=false` (нет тихого fallback в full scan) |
| `conflicting_execution_mode` | 400 | `execution_mode=lab_unrestricted` + `quick` payload |
| `unknown_quick_profile` | 400 | неизвестный `quick.profile` |
| `plan_not_applicable` | 404 | `GET /scans/{id}/plan` для non-quick скана |

При `execution_mode=quick` сервер форсирует `scan_mode="quick"` (глубина для VA planner). Quick **не** наследует `lab_unrestricted`.

**ScanOptions** (из ARGUS/Frontend page.tsx; `scanType` не ломать):

```ts
{
  scanType: "quick" | "light" | "deep";
  reportFormat: "pdf" | "html" | "json" | "xml";
  rateLimit: "slow" | "normal" | "fast" | "aggressive";
  ports: string;                    // "80,443,8080,8443"
  followRedirects: boolean;
  vulnerabilities: {
    xss: boolean; sqli: boolean; csrf: boolean;
    ssrf: boolean; lfi: boolean; rce: boolean;
  };
  authentication: {
    enabled: boolean;
    type: "basic" | "bearer" | "cookie";
    username: string; password: string; token: string;
  };
  scope: {
    maxDepth: number;               // 1-10
    includeSubs: boolean;
    excludePatterns: string;
  };
  advanced: {
    timeout: number;                // 5-120 sec
    userAgent: "chrome" | "firefox" | "mobile" | "bot";
    proxy: string;
    customHeaders: string;           // "Header: value\n..."
  };
}
```

### 1.2 Отчёты

**Список:** Frontend (`getReportByTarget`) запрашивает `GET /reports?target=…` и ожидает **JSON-массив** записей отчётов (берётся первый элемент).

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `GET /reports` | GET | Query: `?target=string` (опционально; фильтр по цели скана) | **`Report[]`** — массив объектов ниже | `{ error: string, code?: string, details?: object }` |
| `GET /reports/:id` | GET | — | **`Report`** + доп. поля детали (ниже) | `{ error: string, code?: string, details?: object }` |
| `GET /reports/:id/download` | GET | Query: см. ниже | Binary/stream (`Content-Disposition: attachment`) | `{ error: string, code?: string, details?: object }` |
| `POST /reports/generate` | POST | ARG-024: `{ scan_id?: string, report_id?: string, tier: "midgard"\|"asgard"\|"valhalla", format: "html"\|"pdf"\|"json"\|"csv"\|"sarif"\|"junit" }` (хотя бы один из `scan_id` / `report_id`) | Файл отчёта + заголовки `X-Argus-Report-*` | 400 / 404 / 503 с телом ошибки как выше |

**`GET /reports/:id/download` — query:**

- `format`: `pdf` \| `html` \| `json` \| `csv` \| `valhalla_sections.csv` (последний только для отчётов tier `valhalla`).
- `regenerate` (optional): `true` — пересобрать экспорт, минуя кэш `ReportObject`/MinIO.
- `redirect` (optional): `true` — редирект `302` на presigned URL вместо потоковой выдачи.

**Report (элемент списка и база для детали):**

```ts
{
  report_id: string;
  target: string;
  summary: ReportSummary;
  findings: Finding[];
  technologies: string[];
  generation_status?: string;  // pending | processing | ready | failed
  tier?: string;               // midgard | asgard | valhalla
  requested_formats?: string[] | null;
}
```

**Дополнительно в `GET /reports/:id`:** `created_at?: string`, `scan_id?: string | null`.

**Finding** — контракт задаёт минимум; сервер может добавлять опциональные поля (`owasp_category`, `confidence`, PoC и т.д.). Клиенты с индексной сигнатурой (`[key: string]: unknown`) остаются совместимыми.

**ReportSummary** (из report/page.tsx):

```ts
{
  critical: number; high: number; medium: number; low: number; info: number;
  technologies: string[];
  sslIssues: number;
  headerIssues: number;
  leaksFound: boolean;
}
```

**Finding** (элемент массива findings в отчёте):

```ts
{
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  cwe?: string;   // CWE-ID, напр. "CWE-79"
  cvss?: number; // 0.0–10.0
  // VHL-PROVABLE-001 (опциональные, additive):
  evidence_classification?: "validated" | "observed" | "candidate" | "inconclusive";
  is_provable?: boolean;        // доказуемо ли из сырых данных
  unconfirmed_reason?: string | null; // причина, если is_provable=false
}
```

**VHL-PROVABLE-001 — Valhalla provability partition.** Для tier `valhalla` отчёт собирается
только из доказуемых сырых данных. В машинном экспорте (`format=json`) поле `findings`
содержит **только доказуемые** находки (`is_provable=true`), а недоказуемые вынесены в
отдельный массив `unconfirmed_findings: Finding[]` (с `is_provable=false` и `unconfirmed_reason`).
В CSV добавлены колонки `is_provable`, `unconfirmed_reason`. В HTML/PDF недоказуемые показаны
в разделе «Unconfirmed Observations» и исключены из заголовочных severity-счётчиков. Для
tier `midgard`/`asgard` поведение не изменилось (`unconfirmed_findings` пустой, `findings`
содержит всё). Frontend Valhalla-вью должен учитывать `unconfirmed_findings`.

### 1.3 Tools (Phase 7)

Инструменты сканирования — POST endpoints. Guardrails: allowlist (nmap, nuclei, nikto, gobuster, sqlmap для `/execute`), валидация target (домен/IP), rate limit, sandbox.

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `POST /tools/execute` | POST | `{ command: string, use_cache?: boolean }` | `{ success: bool, stdout: string, stderr: string, return_code: number, execution_time: number }` | 400, 429 |
| `POST /tools/nmap` | POST | `{ target, scan_type?, ports?, additional_args? }` | То же | 400 |
| `POST /tools/nuclei` | POST | `{ target, severity?, tags?, template?, additional_args? }` | То же | 400 |
| `POST /tools/nikto` | POST | `{ target, additional_args? }` | То же | 400 |
| `POST /tools/gobuster` | POST | `{ url, mode?, wordlist?, additional_args? }` | То же | 400 |
| `POST /tools/sqlmap` | POST | `{ url, data?, additional_args? }` | То же | 400 |

Дополнительные инструменты (dirb, ffuf, subfinder, hydra, wpscan, httpx, amass, feroxbuster, dirsearch, wfuzz, rustscan, masscan, trivy) — аналогичная схема.

### 1.4 Auth (Phase 3)

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `POST /auth/login` | POST | `{ mail: string, password: string }` | `{ status: "success", access_token: string, token_type: "bearer" }` | 503 (JWT_SECRET missing) |
| `GET /auth/me` | GET | Header: `Authorization: Bearer <token>` или `X-API-Key` | `{ user_id, tenant_id, is_api_key }` | 401 |

### 1.5 Health & Metrics

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `GET /health` | GET | — | `{ status: string, version?: string }` | — |
| `GET /metrics` | GET | — | Prometheus text format | — |

---

## 2. Референс: pentagi REST (auth)

Base URL: `/api/v1`. Используется axios с `withCredentials: true` (cookies).

| Endpoint | Method | Request | Response | Error |
|----------|--------|---------|----------|-------|
| `GET /info` | GET | — | `{ status: "success" \| "error", data?: AuthInfo, error?: string }` | 401 → redirect to /login |
| `POST /auth/login` | POST | `{ mail: string, password: string }` | `{ status: "success" \| "error", data?: unknown, error?: string }` | `{ error: string }` |
| `GET /auth/logout` | GET | — | — | — |
| `PUT /user/password` | PUT | `{ current_password: string, password: string, confirm_password: string }` | — | 400: `{ "": string[] }` (validation) |

**AuthInfo:**

```ts
{
  type: "guest" | "user";
  user?: User;
  expires_at?: string;
  issued_at?: string;
  privileges?: string[];
  providers?: string[];
  role?: { id: number; name: string };
  oauth?: boolean;
  develop?: boolean;
}
```

**Error codes (403):** `AuthRequired`, `NotPermitted`, `PrivilegesRequired`, `AdminRequired`, `SuperRequired` → redirect to login.

---

## 3. Референс: pentagi GraphQL

Endpoint: `/api/v1/graphql`  
Transport: HTTP (queries/mutations), WebSocket (subscriptions)

### Queries

| Operation | Variables | Описание |
|-----------|-----------|----------|
| `flows` | — | Список flows |
| `flow` | `flowId` | Один flow |
| `providers` | — | Провайдеры |
| `settings`, `settingsProviders`, `settingsPrompts`, `settingsUser` | — | Настройки |
| `tasks`, `assistants`, `assistantLogs`, `agentLogs`, `messageLogs`, `terminalLogs`, `screenshots`, `searchLogs`, `vectorStoreLogs` | `flowId`, `assistantId`? | Данные flow |
| `flowReport` | `flowId` | Отчёт flow |
| `usageStats*`, `toolcallsStats*`, `flowsStats*` | period, flowId? | Статистика |
| `apiTokens`, `apiToken` | tokenId? | API токены |

### Mutations

| Operation | Описание |
|-----------|----------|
| `addFavoriteFlow`, `deleteFavoriteFlow` | Избранное |
| `createFlow`, `deleteFlow`, `renameFlow` | CRUD flows |
| `putUserInput`, `finishFlow`, `stopFlow` | Управление flow |
| `createAssistant`, `callAssistant`, `stopAssistant`, `deleteAssistant` | Assistants |
| `testAgent`, `testProvider` | Тесты |
| `createProvider`, `updateProvider`, `deleteProvider` | Провайдеры |
| `validatePrompt`, `createPrompt`, `updatePrompt`, `deletePrompt` | Промпты |
| `createApiToken`, `updateApiToken`, `deleteApiToken` | API токены |

### Subscriptions (WebSocket)

| Subscription | Variables | Описание |
|---------------|-----------|----------|
| `terminalLogAdded`, `messageLogAdded`, `messageLogUpdated` | `flowId` | Логи |
| `screenshotAdded`, `agentLogAdded`, `searchLogAdded`, `vectorStoreLogAdded` | `flowId` | Ресурсы |
| `assistantCreated`, `assistantUpdated`, `assistantDeleted`, `assistantLogAdded`, `assistantLogUpdated` | `flowId`, `assistantId`? | Assistants |
| `flowCreated`, `flowUpdated`, `flowDeleted` | — | Flows |
| `taskCreated`, `taskUpdated` | `flowId` | Tasks |
| `providerCreated`, `providerUpdated`, `providerDeleted` | — | Провайдеры |
| `apiTokenCreated`, `apiTokenUpdated`, `apiTokenDeleted` | — | API токены |
| `settingsUserUpdated` | — | Настройки пользователя |

---

## 4. HTTP Status Codes

| Code | Использование |
|------|---------------|
| 200 | Success |
| 201 | Created (POST /scans) |
| 400 | Validation error, bad request |
| 401 | Unauthorized (auth required) |
| 403 | Forbidden (permission denied) |
| 404 | Not found |
| 500 | Internal server error |

---

## 4a. Web Security Workbench — Projects (WB-P1b)

Версионированные, tenant-scoped (RLS) endpoints фундамента Workbench. Все
запросы используют `X-Tenant-ID` (или default tenant) как контекст; сессия
получает `set_session_tenant`, дополнительно каждый запрос фильтрует
`tenant_id`. Планы/статусы: см. `ai_docs/develop/plans/2026-07-22-argus-web-workbench.md`.

| Method | Path | Body | Success | Ошибки |
|--------|------|------|---------|--------|
| POST | `/api/v1/wb/projects` | `WorkbenchProjectCreate` | 201 `WorkbenchProjectDTO` | 409 name conflict, 422 validation |
| GET | `/api/v1/wb/projects` | — (`?status&offset&limit`) | 200 `WorkbenchProjectListResponse` | — |
| GET | `/api/v1/wb/projects/{project_id}` | — | 200 `WorkbenchProjectDTO` | 404 not found |
| PATCH | `/api/v1/wb/projects/{project_id}` | `WorkbenchProjectUpdate` | 200 `WorkbenchProjectDTO` | 404, 409 version/name conflict |
| POST | `/api/v1/wb/projects/{project_id}/eap` | `EapAttachRequest` | 201 `WorkbenchEapView` | 404, 422 `eap rejected: <reason>` |

**Схемы (Pydantic `extra="forbid"`):**

- `WorkbenchProjectCreate` = `{ name, description?, scope_rules[≥1], secrets_ref? }`,
  где `scope_rules[]` — `src.policy.scope.ScopeRule` `{ kind: url|domain|host|ip|cidr,
  pattern, deny?, ports?[{low,high}], note? }`. Секреты не принимаются — только `secrets_ref`.
- `WorkbenchProjectUpdate` = `{ expected_version, name?, description?, status?, scope_rules?, secrets_ref? }`
  (optimistic locking: `expected_version` обязателен).
- `WorkbenchProjectDTO` = `{ id, tenant_id, name, description?, status, scope_rules[], secrets_ref?,
  version, eap?: WorkbenchEapView, created_at, updated_at }`.
- `WorkbenchEapView` = `{ engagement_id, status: verified|invalid|expired, signer_key_id?, expires? }`.
- `EapAttachRequest` = `{ signed_profile: <signed EngagementAuthorizationProfile JSON> }`.
  Верификация fail-closed: неподписанный/битый/просроченный профиль → 422; ключи
  берутся из `WB_EAP_KEYS_DIR` (пустая директория → любой EAP отклоняется).

**Инварианты:** scope default-deny (нужно ≥1 allow-правило); RLS изолирует tenants;
EAP только `verified` персистится; ошибки не раскрывают stack trace/внутренности.

## 4b. Web Security Workbench — Proxy (WB-P2a-2, CA issuance WB-P2b-1)

Прокси-листенеры и история трафика (tenant-scoped, RLS). CA issuance/rotation
(WB-P2b-1) запечатывает приватный ключ CA внешним KEK и возвращает только public
cert. Live-capture через mitm-демон — WB-P2b-2.

| Method | Path | Body | Success | Ошибки |
|--------|------|------|---------|--------|
| POST | `/api/v1/wb/projects/{project_id}/proxy/listeners` | `ProxyListenerCreate` | 201 `ProxyListenerDTO` | 404 project, 409 name conflict |
| GET | `/api/v1/wb/projects/{project_id}/proxy/listeners` | — | 200 `ProxyListenerDTO[]` | — |
| GET | `/api/v1/wb/proxy/listeners/{listener_id}` | — | 200 `ProxyListenerDTO` | 404 |
| PATCH | `/api/v1/wb/proxy/listeners/{listener_id}` | `ProxyListenerUpdate` | 200 `ProxyListenerDTO` | 404, 409 version/name |
| POST | `/api/v1/wb/proxy/listeners/{listener_id}/ca` | `CaIssueRequest` | 200 `ProxyListenerDTO` | 404, 409 version, 503 no sealing key |
| GET | `/api/v1/wb/projects/{project_id}/proxy/history` | — (`?host&offset&limit`) | 200 `TrafficListResponse` | — |
| GET | `/api/v1/wb/proxy/messages/{message_id}` | — | 200 `TrafficMessageDTO` | 404 |

**Схемы (`extra="forbid"`):**

- `ProxyListenerCreate` = `{ name, host?, port?, intercept_enabled?, intercept_rules?: InterceptRuleSet }`.
- `ProxyListenerUpdate` = `{ expected_version, name?, host?, port?, status?, intercept_enabled?, intercept_rules? }` (optimistic lock).
- `CaIssueRequest` = `{ expected_version, common_name? }` (optimistic lock; issue или rotate).
- `InterceptRuleSet` = `{ rules[]: { action: intercept|pass|drop, methods?, host_suffix?, path_prefix?, content_type_contains? }, default_action }`.
- `ProxyListenerDTO` = `{ id, tenant_id, project_id, name, host, port, status: active|disabled|killed,
  intercept_enabled, intercept_rules?, ca?: { fingerprint_sha256, certificate_pem }, version, created_at, updated_at }` — **только public CA cert**.
- `TrafficMessageDTO` = `{ id, project_id, listener_id?, source, method, scheme, host, port, path, query?,
  http_version, status_code?, forward_outcome: forward|blocked, block_reason?, in_scope,
  request_body?: BodyRef, response_body?: BodyRef, tags[], created_at }`.
- `BodyRef` = `{ id, direction, storage_backend: inline|s3|none, sha256, size_bytes, content_type?, truncated }` — **никогда не сами байты тела**.

**Инварианты:** RLS изоляция всех proxy-таблиц; forward только через `ForwardGate`(scope)+`PreflightChecker`(P2b);
тело капается (`plan_body`: inline/spill/truncated) — no unbounded in-memory, тело не логируется;
CA private key — только `export_private_key_pem`, запечатывается Fernet-KEK
(`WB_CA_SEALING_KEY`) перед хранением в `ca_sealed_key` (никогда plaintext/в логах),
`ca_secrets_ref` фиксирует KEK; fail-closed 503 если KEK не сконфигурирован.

---

## 4c. Web Security Workbench — Tools (Decoder + Comparer, WB-P3a)

Stateless утилиты (без БД/scope), требуют auth (tenant). Бинарные данные —
стандартный base64 (byte-safe транспорт). Keyed decoder-операции fail-closed (400):
секреты никогда не пересекают API.

| Method | Path | Body | Success | Ошибки |
|--------|------|------|---------|--------|
| POST | `/api/v1/wb/tools/decoder` | `DecoderRequest` | 200 `DecoderResponse` | 400 bad base64 / decode failed |
| POST | `/api/v1/wb/tools/comparer` | `ComparerRequest` | 200 `ComparerResponse` | 400 bad base64 / compare failed |
| POST | `/api/v1/wb/tools/message-format` | `MessageFormatRequest` | 200 `MessageFormatResponse` | 400 bad base64 |

**Схемы (`extra="forbid"`):**

- `DecoderRequest` = `{ input_base64, steps[]: { operation, options: {str:str} } }` (steps ≤32, options ≤8).
  Операции: `url_(en|de)code`, `base64[url]_(en|de)code`, `hex_(en|de)code`, `html_(en|de)code`,
  `gzip_(compress|decompress)`, `jwt_decode` (header+payload, БЕЗ verify), `hash` (md5/sha1/sha256/384/512),
  `hmac` (только через `secret_ref` — inline `key`/`secret` отклоняются; без resolver → 400).
- `DecoderResponse` = `{ output_base64, output_utf8?: str|null, operations_applied }`.
- `ComparerRequest` = `{ left_base64, right_base64, kind: byte|word|line|json|dom }`.
- `ComparerResponse` = `{ kind, identical, inserted, deleted, replaced, segments[]: { op: equal|insert|delete|replace, a, b } }`.
- `MessageFormatRequest` = `{ raw_base64, message_kind: request|response }`.
- `MessageFormatResponse` = `{ valid, error?, start_line?, headers[]: { name, value }, pretty?: str|null, hex_dump, body_size }`
  — pretty/hex — read-only проекции; исходные raw-байты не мутируются (byte-exact override).

**Инварианты:** чистые/детерминированные; no side effects; gzip-inflate ограничен (16 MiB, anti-bomb);
JSON-diff order-insensitive; DOM-diff игнорирует порядок атрибутов/пробелы; keyed-hash только `secret_ref`;
message-format сохраняет байт-в-байт (pretty/hex — производные, не для транспорта).

---

## 4d. Web Security Workbench — Organizer (WB-P3c)

Коллекции и сохранённые запросы/заметки (tenant-scoped, RLS, optimistic lock).
Сырые байты — base64 (byte-safe), возвращаются только в single-item GET.

| Method | Path | Body | Success | Ошибки |
|--------|------|------|---------|--------|
| POST | `/api/v1/wb/projects/{project_id}/organizer/collections` | `OrganizerCollectionCreate` | 201 `OrganizerCollectionDTO` | 404 project, 409 name |
| GET | `/api/v1/wb/projects/{project_id}/organizer/collections` | — | 200 `OrganizerCollectionDTO[]` | — |
| GET | `/api/v1/wb/organizer/collections/{collection_id}` | — | 200 `OrganizerCollectionDTO` | 404 |
| PATCH | `/api/v1/wb/organizer/collections/{collection_id}` | `OrganizerCollectionUpdate` | 200 `OrganizerCollectionDTO` | 404, 409 version/name |
| DELETE | `/api/v1/wb/organizer/collections/{collection_id}` | — | 204 | 404 |
| POST | `/api/v1/wb/organizer/collections/{collection_id}/items` | `OrganizerItemCreate` | 201 `OrganizerItemDTO` | 404 collection, 400 bad base64 |
| GET | `/api/v1/wb/projects/{project_id}/organizer/items` | — (`?collection_id&host&tag&q&offset&limit`) | 200 `OrganizerItemListResponse` | — |
| GET | `/api/v1/wb/organizer/items/{item_id}` | — | 200 `OrganizerItemDTO` (с raw) | 404 |
| PATCH | `/api/v1/wb/organizer/items/{item_id}` | `OrganizerItemUpdate` | 200 `OrganizerItemDTO` | 404, 409 version |
| DELETE | `/api/v1/wb/organizer/items/{item_id}` | — | 204 | 404 |

**Схемы (`extra="forbid"`):**

- `OrganizerCollectionCreate` = `{ name, description? }`; `OrganizerCollectionUpdate` = `{ expected_version, name?, description? }`.
- `OrganizerCollectionDTO` = `{ id, tenant_id, project_id, name, description?, version, created_at, updated_at }`.
- `OrganizerItemCreate` = `{ title, method?, host?, url?, notes?, tags[]≤32, raw_request_base64?, raw_response_base64?, source_message_id? }` (raw ≤~1 MiB).
- `OrganizerItemUpdate` = `{ expected_version, title?, notes?, tags? }`.
- `OrganizerItemDTO` = `{ id, tenant_id, project_id, collection_id, title, method?, host?, url?, notes?, tags[],
  has_raw_request, has_raw_response, raw_request_base64?, raw_response_base64?, source_message_id?, version, created_at, updated_at }`
  — `raw_*_base64` заполняются ТОЛЬКО в single-item GET (в list — `null`).
- `OrganizerItemListResponse` = `{ items[], total, offset, limit }`.

**Инварианты:** RLS изоляция collections/items; сырые байты хранятся byte-exact и не логируются;
поиск по `collection_id`/`host`/`tag`(JSONB containment)/`q`(title ilike); tags дедуплицируются/тримятся.

---

## 4e. Web Security Workbench — Repeater (WB-P3b-2)

Сохранённые редактируемые запросы (tabs) + scope-gated replay с историей.
Сырые байты — base64, byte-exact; возвращаются только в single-item GET.

| Method | Path | Body | Success | Ошибки |
|--------|------|------|---------|--------|
| POST | `/api/v1/wb/projects/{project_id}/repeater/tabs` | `RepeaterTabCreate` | 201 `RepeaterTabDTO` | 404 project, 400 base64 |
| GET | `/api/v1/wb/projects/{project_id}/repeater/tabs` | — | 200 `RepeaterTabDTO[]` | — |
| GET | `/api/v1/wb/repeater/tabs/{tab_id}` | — | 200 `RepeaterTabDTO` | 404 |
| PATCH | `/api/v1/wb/repeater/tabs/{tab_id}` | `RepeaterTabUpdate` | 200 `RepeaterTabDTO` | 404, 409 version, 400 base64 |
| DELETE | `/api/v1/wb/repeater/tabs/{tab_id}` | — | 204 | 404 |
| POST | `/api/v1/wb/repeater/tabs/{tab_id}/replay` | `RepeaterReplayRequest` | 200 `RepeaterExchangeDTO` | 404, 409 not-active, 400 malformed, 502 upstream |
| GET | `/api/v1/wb/repeater/tabs/{tab_id}/exchanges` | — (`?offset&limit`) | 200 `RepeaterExchangeListResponse` | — |
| GET | `/api/v1/wb/repeater/exchanges/{exchange_id}` | — | 200 `RepeaterExchangeDTO` (с raw) | 404 |

**Схемы (`extra="forbid"`):**

- `RepeaterTabCreate` = `{ name, raw_request_base64 }`; `RepeaterTabUpdate` = `{ expected_version, name?, raw_request_base64? }`.
- `RepeaterTabDTO` = `{ id, tenant_id, project_id, name, scheme?, host?, port?, raw_request_base64, version, created_at, updated_at }`.
- `RepeaterReplayRequest` = `{ raw_request_base64? }` (нет → реплеится сохранённый запрос tab; есть → byte-exact override).
- `RepeaterExchangeDTO` = `{ id, tenant_id, project_id, tab_id, forward_outcome, block_reason?, status_code?, response_size,
  truncated, duration_ms?, raw_request_base64?, raw_response_base64?, created_at }` — `raw_*_base64` только в single-item GET.
- `RepeaterExchangeListResponse` = `{ items[], total, offset, limit }`.

**Инварианты:** replay ТОЛЬКО через `RepeaterService` (scope → optional preflight; при block `HttpSender` не вызывается);
kill-switch — replay запрещён если project.status ≠ `active` (409); каждый replay (forward/blocked) записан в history;
raw byte-exact, не логируется; response bounded (5 MiB, `truncated`); TLS-verify off (scope-gated authorized pentest, live-send infra-gated).

## 4f. Web Security Workbench — Intruder (WB-P4b)

Автоматизированные атаки (Sniper/Battering-ram/Pitchfork/Cluster-bomb). API только
*диспетчеризует* исполнение в изолированный Celery-пул `argus.intruder.highvol`; сам
send-loop проходит через `ForwardGate` (scope). Payload'ы — только ссылки в подписанный
`PayloadRegistry` (SI-5). Результаты — metadata-only (без raw payload/тел).

| Method | Path | Body | Success | Ошибки |
|--------|------|------|---------|--------|
| POST | `/api/v1/wb/projects/{project_id}/intruder/attacks` | `IntruderAttackCreate` | 201 `IntruderAttackDTO` | 404 project, 409 name, 400 base64 |
| GET | `/api/v1/wb/projects/{project_id}/intruder/attacks` | — | 200 `IntruderAttackDTO[]` | — |
| GET | `/api/v1/wb/intruder/attacks/{attack_id}` | — | 200 `IntruderAttackDTO` | 404 |
| POST | `/api/v1/wb/intruder/attacks/{attack_id}/start` | `IntruderControlRequest` | 200 `IntruderAttackDTO` | 404, 409 not-active/version |
| POST | `/api/v1/wb/intruder/attacks/{attack_id}/pause` | `IntruderControlRequest` | 200 `IntruderAttackDTO` | 404, 409 version |
| POST | `/api/v1/wb/intruder/attacks/{attack_id}/resume` | `IntruderControlRequest` | 200 `IntruderAttackDTO` | 404, 409 not-active/version |
| POST | `/api/v1/wb/intruder/attacks/{attack_id}/cancel` | `IntruderControlRequest` | 200 `IntruderAttackDTO` | 404, 409 version |
| GET | `/api/v1/wb/intruder/attacks/{attack_id}/requests` | — (`?flagged&offset&limit`) | 200 `IntruderRequestListResponse` | — |

**Схемы (`extra="forbid"`):**

- `IntruderAttackCreate` = `{ name, attack_type, raw_request_template_base64, positions?[], payload_config?, config? }`;
  `attack_type` ∈ `sniper|battering_ram|pitchfork|cluster_bomb`; `payload_config` = `{ sets: [{ family_id, encoding_pipeline?,
  parameters?, max_payloads?, approval_id?, correlation_key? }] }` (ссылки в реестр, не raw).
- `IntruderControlRequest` = `{ expected_version }` (optimistic lock).
- `IntruderAttackDTO` = `{ id, tenant_id, project_id, name, attack_type, status, raw_request_template_base64, positions?,
  payload_config?, config?, checkpoint?, requests_total, requests_completed, findings_total, error_reason?, version,
  created_at, updated_at }`.
- `IntruderRequestDTO` = `{ id, tenant_id, project_id, attack_id, request_index, payload_label?, payload_index?,
  forward_outcome, block_reason?, status_code?, response_length?, response_time_ms?, response_sha256?, flagged, error_reason?,
  created_at }`; `IntruderRequestListResponse` = `{ items[], total, offset, limit }`.

**Инварианты:** каждый запрос проходит `ForwardGate` (scope) в `IntruderService`; kill-switch — start/resume запрещены при
project.status ≠ `active` (409), `cancel` пишет терминальный статус, который воркер видит и дропает; payload'ы только через
`PayloadBuilder`/registry; result-строки без raw payload (только `payload_label` = ссылка). Live high-volume send — infra-gated.

## 4g. Web Security Workbench — Sessions (WB-P6b)

Session macros (login-replay) + principals (owner/attacker/anonymous) для авторизационного
тестирования. Split-plane secrets (SI-3): raw-креды не принимаются и не возвращаются — только
`secret_ref` в шагах макроса и `secrets_ref`-хэндл у principal.

| Method | Path | Body | Success | Ошибки |
|--------|------|------|---------|--------|
| POST | `/api/v1/wb/projects/{project_id}/sessions/macros` | `SessionMacroCreate` | 201 `SessionMacroDTO` | 404 project, 409 name |
| GET | `/api/v1/wb/projects/{project_id}/sessions/macros` | — | 200 `SessionMacroDTO[]` | — |
| GET | `/api/v1/wb/sessions/macros/{macro_id}` | — | 200 `SessionMacroDTO` | 404 |
| PATCH | `/api/v1/wb/sessions/macros/{macro_id}` | `SessionMacroUpdate` | 200 `SessionMacroDTO` | 404, 409 version/name |
| DELETE | `/api/v1/wb/sessions/macros/{macro_id}` | — | 204 | 404 |
| POST | `/api/v1/wb/projects/{project_id}/sessions/principals` | `SessionPrincipalCreate` | 201 `SessionPrincipalDTO` | 404 project/macro, 409 name, 422 role |
| GET | `/api/v1/wb/projects/{project_id}/sessions/principals` | — | 200 `SessionPrincipalDTO[]` | — |
| GET | `/api/v1/wb/sessions/principals/{principal_id}` | — | 200 `SessionPrincipalDTO` | 404 |
| PATCH | `/api/v1/wb/sessions/principals/{principal_id}` | `SessionPrincipalUpdate` | 200 `SessionPrincipalDTO` | 404, 409 version/name, 422 role |
| DELETE | `/api/v1/wb/sessions/principals/{principal_id}` | — | 204 | 404 |

**Схемы (`extra="forbid"`):**

- `SessionMacroCreate` = `{ name, steps?[], match_rules?, config? }`; `SessionMacroUpdate` = `{ expected_version, name?, steps?, match_rules?, config? }`.
- `SessionMacroDTO` = `{ id, tenant_id, project_id, name, steps?, match_rules?, config?, version, created_at, updated_at }`.
- `SessionPrincipalCreate` = `{ name, role, secrets_ref?, macro_id?, config? }`; `role` ∈ `owner|attacker|anonymous`;
  `SessionPrincipalUpdate` = `{ expected_version, name?, role?, secrets_ref?, macro_id?, config? }`.
- `SessionPrincipalDTO` = `{ id, tenant_id, project_id, name, role, secrets_ref?, macro_id?, config?, version, created_at, updated_at }`.

**Инварианты:** split-plane secrets (SI-3) — ни один endpoint не принимает/не возвращает raw-креды (только `secret_ref`/`secrets_ref`);
optimistic lock (409); live owner/attacker replay через `ForwardGate`+preflight+EAP на воркер-плоскости — infra-gated (этот роутер
хранит только определения).

---

## 4.1 Unified AI / LAB / Nuclei / RAG (2026-08-15)

Base: `/api/v1`. Tenant header `X-Tenant-Id` required on mutating engagement routes. LAB mutating execution requires a **usable** lab lease (`requires_approval` always `false` after lease).

| Endpoint | Method | Request | Success |
|----------|--------|---------|---------|
| `/engagements/{id}/execution-mode` | GET/POST | `{ mode }` | `{ engagement_id, tenant_id, mode, first_execution_at }` |
| `/engagements/{id}/lab-scope` | POST | cidrs/dns/k8s/vm | 201 LabScopeManifest |
| `/engagements/{id}/lab-lease` | POST | `{ target, ... }` | 201 lease + allow-all policy; 403 outside boundary |
| `/nuclei/profiles` | GET | — | `{ profiles[] }` |
| `/nuclei/templates` | GET | — | `{ templates[] }` |
| `/nuclei/templates/ingest` | POST | `{ content, template_id?, source, mode }` | 201 manifest |
| `/nuclei/templates/generate` | POST | `{ intent, mode=lab_unrestricted }` | 201 generated artifact |
| `/nuclei/templates/{id}/validate` | POST | query `mode` | `{ allowed, requires_approval, analysis }` |
| `/nuclei/releases` | GET | — | `{ releases[], active_release_id }` |
| `/nuclei/releases` | POST | `{ version, digest_sha256, provenance? }` | 201 release |
| `/nuclei/releases/{id}/activate` | POST | — | active release |
| `/nuclei/releases/{id}/rollback` | POST | — | rolled_back release |
| `/api-surface/ingest` | POST | `{ asset_id, document, mode, base_url? }` | 201 ApiDocumentDTO |
| `/assets/{id}/endpoints` | GET | — | `{ asset_id, endpoints[] }` |
| `/assets/{id}/capabilities` | GET | — | `{ asset_id, capability_ids[] }` |
| `/scans/{id}/coverage` | GET | — | `{ scan_id, results[] }` from coverage sink |
| `/scans/{id}/occurrences` | GET | header `X-Tenant-Id` | `{ scan_id, occurrences[] }`; 400 `tenant_required`; `occurrence_key`/`finding_key` are sha256 (64 hex) |
| `/scans/{id}/diff/{baseline_id}` | GET | — | `{ entries[] }` |
| `/findings/{key}/assessments` | POST | `{ classification, observation?, scan_id? }` | finding (append-only) |
| `/findings/{key}/retest` | POST | query `scan_id`, `outcome` | job + finding |
| `/lab/scripts` | POST | `{ language, source, argv?, lease_id }` | 201; 403 without usable lease |
| `/lab/scripts/{id}/execute` | POST | query `lease_id?` | 200 `{ status, return_code, stdout, stderr, runner, requires_approval: false }`; 403 `lab_lease_required`; 409 `lab_namespace_mismatch` |
| `/lab/artifacts/{id}/execute` | POST | `{ lease_id, argv? }` | 200 real execution (nuclei YAML via compiler when ingested); 403 without lease |
| `/lab/executions/{id}` | GET | — | execution row |
| `/rag/traces` | POST | `{ scan_id, query, citations[] }` | 201 |
| `/rag/traces/{scan_id}` | GET | — | citation trace |
| `/oast/traces` | POST | `{ scan_id, protocol, token_id?, payload_hash? }` — `correlation_status` from client is ignored | 201 `{ scan_id, protocol, correlation_status, token_id, payload_hash }` where status is computed: `uncorrelated` (no/invalid token), `correlated` (issued token ingested), `unknown_token` |
| `/oast/traces/{scan_id}` | GET | — | `{ scan_id, interactions[] }` |

**Инварианты:** production сохраняет signature/approval gates; LAB после verified lease — `allowed_tools/actions/protocols/payloads=*`, `requires_approval=false`. AI не удаляет findings.

---

## 5. Связанные документы

- [README.md](./README.md) — индекс документации
- [architecture-decisions.md](./architecture-decisions.md) — ADR
- [env-vars.md](./env-vars.md) — переменные окружения
- [auth-flow.md](./auth-flow.md) — поток аутентификации
- [sse-polling.md](./sse-polling.md) — SSE vs Polling
- [../ai_docs/develop/plans/2026-07-22-argus-web-workbench.md](../ai_docs/develop/plans/2026-07-22-argus-web-workbench.md) — Web Workbench план + capability matrix
