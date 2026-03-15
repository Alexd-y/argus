# ARGUS API Contracts

**Источник истины:** ARGUS/Frontend (и test/pentagi/frontend как референс).  
**Правило:** Backend реализуется строго по этим контрактам.

---

## 1. REST API (ARGUS Scanner)

Base URL: `/api/v1` (или `NEXT_PUBLIC_API_URL`)

### 1.1 Сканирование

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `POST /scans` | POST | `{ target: string, email: string, options: ScanOptions }` | `{ scan_id: string, status: string, message?: string }` | `{ error: string, code?: string, details?: object }` |
| `GET /scans/:id` | GET | — | `{ id: string, status: string, progress: number, phase: string, target: string, created_at: string }` | `{ error: string, code?: string }` |
| `GET /scans/:id/events` | GET (SSE) | — | SSE stream: `{ event: string, phase?: string, progress?: number, message?: string, data?: object }` | — |

**ScanOptions** (из ARGUS/Frontend page.tsx):

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

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `GET /reports` | GET | Query: `?target=string` | `{ report_id: string, target: string, summary: ReportSummary, findings: Finding[], technologies: string[], ... }` | `{ error: string, code?: string }` |
| `GET /reports/:id` | GET | — | Full report object | `{ error: string, code?: string }` |
| `GET /reports/:id/download` | GET | Query: `?format=pdf\|html\|json\|csv` | Binary/stream | `{ error: string, code?: string }` |

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
}
```

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

## 5. Связанные документы

- [README.md](./README.md) — индекс документации
- [architecture-decisions.md](./architecture-decisions.md) — ADR
- [env-vars.md](./env-vars.md) — переменные окружения
- [auth-flow.md](./auth-flow.md) — поток аутентификации
- [sse-polling.md](./sse-polling.md) — SSE vs Polling
