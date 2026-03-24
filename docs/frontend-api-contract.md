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

All paths below are under **`/api/v1`** (e.g. full URL `POST /api/v1/scans`, `POST /api/v1/scans/{id}/reports/generate`). See [reporting.md](./reporting.md) for pipeline architecture (RPT-010).

### 2.1 Scans

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `POST /scans` | POST | `CreateScanRequest` | `CreateScanResponse` | `ApiError` |
| `GET /scans/:id` | GET | — | `ScanStatus` | `ApiError` |
| `GET /scans/:id/findings` | GET | — | `Finding[]` | `ApiError` |
| `POST /scans/:id/reports/generate` | POST | `ReportGenerateRequest` | `ReportGenerateAcceptedResponse` | `ApiError` |
| `GET /scans/:id/events` | GET (SSE) | — | SSE stream: `SSEEventPayload` | — |

**Auth:** None (current frontend does not send auth headers for scans).

**Report generation (`POST /scans/:id/reports/generate`):**

- **Status:** `202 Accepted` — report row is created and background generation is queued (Celery `argus.generate_report`).
- **Body:** `type` — report tier `midgard` \| `asgard` \| `valhalla`; `formats` — non-empty array of `pdf` \| `html` \| `json` \| `csv` (duplicates removed, lowercased).
- **Response:** `report_id` (UUID string), `task_id` (Celery task id when available, else `null`).

Poll **`GET /api/v1/reports/:report_id`** (or list **`GET /api/v1/reports`**) for `generation_status`, `tier`, and summary; when `generation_status === "ready"`, download via **`GET /api/v1/reports/:report_id/download?format=...`**.

### 2.2 Reports

| Endpoint | Method | Request Schema | Response Schema | Error Schema |
|----------|--------|----------------|-----------------|--------------|
| `GET /reports?target={string}` | GET | Query: optional `target` | `ReportListItem[]` (see below) | `ApiError` |
| `GET /reports/:id` | GET | — | `ReportDetail` | `ApiError` |
| `GET /reports/:id/download?format={format}` | GET | Query: `format`; optional `regenerate`, `redirect` | Binary stream or `302` to presigned URL | `ApiError` |

**Auth:** None (current frontend does not send auth headers for reports).

**Report download formats:** `pdf`, `html`, `json`, `csv`.

**Query flags (download):**

- `regenerate=true` — bypass MinIO cache, re-render and re-upload.
- `redirect=true` — respond with redirect to presigned URL when cached object exists (or after upload).

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

### 4.9 Report (list item)

List endpoint aligns with backend `ReportListResponse`:

```ts
type ReportGenerationStatus = "pending" | "processing" | "ready" | "failed";

interface ReportListItem {
  report_id: string;
  target: string;
  summary: ReportSummary;
  findings: Finding[];
  technologies: string[];
  generation_status: ReportGenerationStatus;
  tier: "midgard" | "asgard" | "valhalla";
  requested_formats: string[] | null;
}
```

### 4.10 Report detail

```ts
interface ReportDetail extends ReportListItem {
  created_at: string | null;
  scan_id: string | null;
}
```

### 4.11 ReportGenerateRequest

```ts
type ReportTier = "midgard" | "asgard" | "valhalla";
type ReportExportFormat = "pdf" | "html" | "json" | "csv";

interface ReportGenerateRequest {
  type: ReportTier;
  formats: ReportExportFormat[];
}
```

### 4.12 ReportGenerateAcceptedResponse

```ts
interface ReportGenerateAcceptedResponse {
  report_id: string;
  task_id: string | null;
}
```

---

## 5. HTTP Status Codes

| Code | Usage |
|------|-------|
| 200 | Success (GET) |
| 201 | Created (POST /scans) |
| **202** | **Accepted (POST /scans/:id/reports/generate — queued)** |
| 400 | Validation error, bad request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found |
| 500 | Internal server error |

Frontend throws on `!res.ok` and uses `body.error` or `Request failed (${res.status})` for user message.

---

## 6. Related Documents

- [reporting.md](./reporting.md) — RPT-010 reporting pipeline, Celery, MinIO, tiers, prompts
- [api-contracts.md](./api-contracts.md) — extended contracts (tools, auth, health)
- [api-contract-rule.md](./api-contract-rule.md) — contract-first rule
- [sse-polling.md](./sse-polling.md) — SSE vs polling details
