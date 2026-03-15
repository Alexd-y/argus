# ARGUS Frontend API Contract

**Source of truth:** ARGUS/Frontend — `src/lib/types.ts`, `api.ts`, `scans.ts`, `reports.ts`, `hooks/useScanProgress.ts`, `hooks/useReport.ts`.

Backend MUST implement these contracts exactly. No changes to names, paths, status codes, or payload shapes without frontend compatibility.

---

## 1. Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `/api/v1` | Base URL for API requests. May be relative or absolute. |

---

## 2. REST API Endpoints

### 2.1 Scans

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `POST /scans` | POST | `CreateScanRequest` | `CreateScanResponse` | `ApiError` |
| `GET /scans/:id` | GET | — | `ScanStatus` | `ApiError` |
| `GET /scans/:id/events` | GET (SSE) | — | SSE stream: `SSEEventPayload` | — |

**Auth:** None (current frontend does not send auth headers for scans).

### 2.2 Reports

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `GET /reports?target={string}` | GET | Query: `target` | `Report[]` | `ApiError` |
| `GET /reports/:id` | GET | — | `Report` | `ApiError` |
| `GET /reports/:id/download?format={format}` | GET | Query: `format` | Binary/stream | `ApiError` |

**Auth:** None (current frontend does not send auth headers for reports).

**Report download formats:** `pdf`, `html`, `json`, `csv`.

---

## 3. Polling & SSE Behavior

### 3.1 Polling

- **Endpoint:** `GET /scans/:id`
- **Interval:** 3 seconds (`POLL_INTERVAL_MS = 3000`)
- **Use case:** Fallback when SSE fails or is unavailable (e.g. `EventSource` not supported, connection error).
- **Stop condition:** When `status === "completed"` or `status === "failed"`.

### 3.2 SSE (Server-Sent Events)

- **Endpoint:** `GET /scans/:id/events`
- **Transport:** `EventSource` (requires absolute URL on client).
- **Event payload:** JSON in `data` field, parsed as `SSEEventPayload`.

**Handled events:**

| event | Description | Frontend behavior |
|-------|-------------|-------------------|
| `complete` | Scan finished successfully | Set status to `complete`, progress to 100, stop polling/SSE |
| `error` | Scan failed | Set status to `error`, set error message, stop polling/SSE |

**Payload fields used:** `event`, `phase`, `progress`, `message`, `error` (for `error` event).

---

## 4. Full Schemas

### 4.1 ApiError

```ts
interface ApiError {
  error: string;
  code?: string;
  details?: unknown;
}
```

Used when `res.ok === false`. Frontend reads `body.error` or `body.detail` for user-facing message (FastAPI returns `detail`).

### 4.2 ScanOptions

```ts
interface ScanOptions {
  scanType: "quick" | "light" | "deep";
  reportFormat: "pdf" | "html" | "json" | "xml";
  rateLimit: "slow" | "normal" | "fast" | "aggressive";
  ports: string;
  followRedirects: boolean;
  vulnerabilities: {
    xss: boolean;
    sqli: boolean;
    csrf: boolean;
    ssrf: boolean;
    lfi: boolean;
    rce: boolean;
  };
  authentication: {
    enabled: boolean;
    type: "basic" | "bearer" | "cookie";
    username: string;
    password: string;
    token: string;
  };
  scope: {
    maxDepth: number;
    includeSubs: boolean;
    excludePatterns: string;
  };
  advanced: {
    timeout: number;
    userAgent: "chrome" | "firefox" | "mobile" | "bot";
    proxy: string;
    customHeaders: string;
  };
}
```

### 4.3 CreateScanRequest

```ts
interface CreateScanRequest {
  target: string;
  email: string;
  options: ScanOptions;
}
```

### 4.4 CreateScanResponse

```ts
interface CreateScanResponse {
  scan_id: string;
  status: string;
  message?: string;
}
```

### 4.5 ScanStatus

```ts
interface ScanStatus {
  id: string;
  status: string;
  progress: number;
  phase: string;
  target: string;
  created_at: string;
}
```

Frontend treats `status === "completed"` as success, `status === "failed"` as error.

### 4.6 SSEEventPayload

```ts
interface SSEEventPayload {
  event?: string;
  phase?: string;
  progress?: number;
  message?: string;
  data?: unknown;
  error?: string;
}
```

For `event === "error"`, frontend reads `payload.error` for user message.

### 4.7 ReportSummary

```ts
interface ReportSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  technologies: string[];
  sslIssues: number;
  headerIssues: number;
  leaksFound: boolean;
}
```

### 4.8 Finding

```ts
interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  cwe?: string;
  cvss?: number;
}
```

### 4.9 Report

```ts
interface Report {
  report_id: string;
  target: string;
  summary: ReportSummary;
  findings: Finding[];
  technologies: string[];
  [key: string]: unknown;
}
```

---

## 5. HTTP Status Codes

| Code | Usage |
|------|-------|
| 200 | Success (GET) |
| 201 | Created (POST /scans) |
| 400 | Validation error, bad request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found |
| 500 | Internal server error |

Frontend throws on `!res.ok` and uses `body.error` or `Request failed (${res.status})` for user message.

---

## 6. Related Documents

- [api-contracts.md](./api-contracts.md) — extended contracts (tools, auth, health)
- [api-contract-rule.md](./api-contract-rule.md) — contract-first rule
- [sse-polling.md](./sse-polling.md) — SSE vs polling details
