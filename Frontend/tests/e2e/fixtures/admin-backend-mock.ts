/**
 * Stand-alone mock of the FastAPI `/api/v1/admin/*` surface used by the
 * Playwright accessibility suite (T26).
 *
 * Why a real HTTP server, not `page.route()`:
 *   The admin pages call FastAPI from Next.js Server Actions running on the
 *   Node side, NOT from the browser. `page.route()` would never see those
 *   requests. Instead we point the dev server's `BACKEND_URL` env at this
 *   mock and let the actions hit a real (loopback) HTTP listener.
 *
 * Security boundary:
 *   The mock NEVER returns tenant secrets, real tokens, or PII. Every
 *   payload is synthetic and contained inside this file. The mock honours
 *   `X-Admin-Key` only nominally — it does not enforce it because the
 *   ADMIN_API_KEY used in the suite is a fixed dev string and the mock is
 *   bound to 127.0.0.1. Production traffic never reaches this code.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "http";
import { AddressInfo } from "net";

const MOCK_TENANT_ID = "00000000-0000-0000-0000-000000000aaa";
const MOCK_SECONDARY_TENANT_ID = "00000000-0000-0000-0000-000000000bbb";
const MOCK_SCAN_ID = "11111111-2222-3333-4444-555555555555";
const MOCK_AUDIT_DRIFT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

const TENANTS: JsonValue[] = [
  {
    id: MOCK_TENANT_ID,
    name: "Acme Demo Tenant",
    exports_sarif_junit_enabled: true,
    rate_limit_rpm: 60,
    scope_blacklist: null,
    retention_days: 90,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-04-01T00:00:00Z",
  },
  {
    id: MOCK_SECONDARY_TENANT_ID,
    name: "Beta Tenant",
    exports_sarif_junit_enabled: false,
    rate_limit_rpm: 30,
    scope_blacklist: ["internal.example.com"],
    retention_days: 60,
    created_at: "2026-01-15T00:00:00Z",
    updated_at: "2026-04-10T00:00:00Z",
  },
];

const FINDINGS: JsonValue[] = [
  {
    id: "f0000001-0000-0000-0000-000000000001",
    tenant_id: MOCK_TENANT_ID,
    scan_id: MOCK_SCAN_ID,
    severity: "critical",
    title: "Outdated TLS configuration on api.example.com",
    status: "open",
    target: "https://api.example.com",
    cve_ids: ["CVE-2024-12345"],
    cvss: 9.1,
    cvss_score: 9.1,
    epss_score: 0.42,
    kev_listed: true,
    ssvc_action: "act",
    discovered_at: "2026-04-15T10:00:00Z",
    updated_at: "2026-04-15T10:00:00Z",
    created_at: "2026-04-15T10:00:00Z",
  },
  {
    id: "f0000002-0000-0000-0000-000000000002",
    tenant_id: MOCK_TENANT_ID,
    scan_id: MOCK_SCAN_ID,
    severity: "high",
    title: "Reflected XSS on /search endpoint",
    status: "open",
    target: "https://app.example.com/search",
    cve_ids: [],
    cvss: 7.4,
    cvss_score: 7.4,
    epss_score: 0.18,
    kev_listed: false,
    ssvc_action: "attend",
    discovered_at: "2026-04-16T11:30:00Z",
    updated_at: "2026-04-16T11:30:00Z",
    created_at: "2026-04-16T11:30:00Z",
  },
  {
    id: "f0000003-0000-0000-0000-000000000003",
    tenant_id: MOCK_SECONDARY_TENANT_ID,
    scan_id: MOCK_SCAN_ID,
    severity: "medium",
    title: "Missing security headers",
    status: "open",
    target: "https://web.example.com",
    cve_ids: [],
    cvss: 5.3,
    cvss_score: 5.3,
    epss_score: null,
    kev_listed: null,
    ssvc_action: "track",
    discovered_at: "2026-04-17T09:00:00Z",
    updated_at: "2026-04-17T09:00:00Z",
    created_at: "2026-04-17T09:00:00Z",
  },
];

const AUDIT_LOGS: JsonValue[] = [
  {
    id: "ev0000001-0000-0000-0000-000000000001",
    created_at: "2026-04-20T08:00:00Z",
    event_type: "scan.created",
    action: "scan.created",
    actor_subject: "admin_console:super-admin",
    user_id: null,
    tenant_id: MOCK_TENANT_ID,
    resource_type: "scan",
    resource_id: MOCK_SCAN_ID,
    details: { source: "admin-console", scan_mode: "fast" },
    severity: "info",
  },
  {
    id: "ev0000002-0000-0000-0000-000000000002",
    created_at: "2026-04-20T08:05:00Z",
    event_type: "finding.suppressed",
    action: "finding.suppressed",
    actor_subject: "admin_console:admin",
    user_id: null,
    tenant_id: MOCK_TENANT_ID,
    resource_type: "finding",
    resource_id: "f0000002-0000-0000-0000-000000000002",
    details: { reason: "duplicate", count: 1 },
    severity: "warning",
  },
  {
    id: MOCK_AUDIT_DRIFT_ID,
    created_at: "2026-04-20T08:10:00Z",
    event_type: "audit.chain.replay",
    action: "audit.chain.replay",
    actor_subject: "admin_console:super-admin",
    user_id: null,
    tenant_id: MOCK_TENANT_ID,
    resource_type: "audit_log",
    resource_id: null,
    details: { window: "2026-04-19/2026-04-20" },
    severity: "info",
  },
];

const SCANS: JsonValue[] = [
  {
    id: MOCK_SCAN_ID,
    status: "completed",
    progress: 100,
    phase: "done",
    target: "https://api.example.com",
    created_at: "2026-04-15T09:00:00Z",
    updated_at: "2026-04-15T09:30:00Z",
    scan_mode: "fast",
  },
  {
    id: "22222222-3333-4444-5555-666666666666",
    status: "running",
    progress: 42,
    phase: "exploit",
    target: "https://web.example.com",
    created_at: "2026-04-19T12:00:00Z",
    updated_at: "2026-04-19T12:15:00Z",
    scan_mode: "deep",
  },
];

const SCAN_DETAIL: JsonValue = {
  id: MOCK_SCAN_ID,
  status: "completed",
  progress: 100,
  phase: "done",
  target: "https://api.example.com",
  created_at: "2026-04-15T09:00:00Z",
  updated_at: "2026-04-15T09:30:00Z",
  scan_mode: "fast",
  tool_metrics: [
    {
      tool_name: "nmap",
      status: "ok",
      duration_sec: 12.5,
      started_at: "2026-04-15T09:00:00Z",
      finished_at: "2026-04-15T09:00:13Z",
    },
    {
      tool_name: "nuclei",
      status: "ok",
      duration_sec: 45.2,
      started_at: "2026-04-15T09:00:14Z",
      finished_at: "2026-04-15T09:01:00Z",
    },
  ],
  error_summary: [],
};

function writeJson(res: ServerResponse, status: number, body: JsonValue): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(text).toString(),
  });
  res.end(text);
}

function writeNotFound(res: ServerResponse): void {
  writeJson(res, 404, { detail: "not_found" });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/**
 * Resolve the URL of an incoming request without depending on the host
 * header (the dev server forwards `127.0.0.1:8902` but we don't need to
 * trust it). We only care about the pathname + query.
 */
function parseUrl(req: IncomingMessage): URL {
  const raw = req.url ?? "/";
  return new URL(raw, "http://localhost");
}

function handleFindings(url: URL, res: ServerResponse): void {
  const tenantFilter = url.searchParams.get("tenant_id");
  const severityFilter = url.searchParams.getAll("severity");
  const offset = Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0;
  const limit = Number.parseInt(url.searchParams.get("limit") ?? "50", 10) || 50;

  let items = FINDINGS.slice();
  if (tenantFilter) {
    items = items.filter(
      (item) => (item as Record<string, JsonValue>)["tenant_id"] === tenantFilter,
    );
  }
  if (severityFilter.length > 0) {
    const allowed = new Set(severityFilter);
    items = items.filter((item) =>
      allowed.has(String((item as Record<string, JsonValue>)["severity"])),
    );
  }

  const total = items.length;
  const sliced = items.slice(offset, offset + limit);
  const hasMore = offset + sliced.length < total;

  writeJson(res, 200, {
    findings: sliced,
    total,
    limit,
    offset,
    has_more: hasMore,
  });
}

function handleBulkSuppress(body: string, res: ServerResponse): void {
  let parsed: { tenant_id?: string; finding_ids?: string[]; reason?: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }
  const ids = Array.isArray(parsed.finding_ids) ? parsed.finding_ids : [];
  writeJson(res, 200, {
    suppressed_count: ids.length,
    skipped_already_suppressed_count: 0,
    audit_id: "ev_bulk_suppress_test",
    results: ids.map((id) => ({ finding_id: id, status: "suppressed" })),
  });
}

function handleAuditLogs(url: URL, res: ServerResponse): void {
  const tenantFilter = url.searchParams.get("tenant_id");
  const eventType = url.searchParams.get("event_type");
  const limit = Number.parseInt(url.searchParams.get("limit") ?? "50", 10) || 50;
  const offset = Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0;

  let items = AUDIT_LOGS.slice();
  if (tenantFilter) {
    items = items.filter(
      (item) => (item as Record<string, JsonValue>)["tenant_id"] === tenantFilter,
    );
  }
  if (eventType) {
    items = items.filter(
      (item) => (item as Record<string, JsonValue>)["event_type"] === eventType,
    );
  }
  // Bare-array shape (matches T22 backend); the schema accepts both.
  writeJson(res, 200, items.slice(offset, offset + limit));
}

function handleVerifyChain(res: ServerResponse): void {
  writeJson(res, 200, {
    ok: true,
    verified_count: AUDIT_LOGS.length,
    last_verified_index: AUDIT_LOGS.length - 1,
    drift_event_id: null,
    drift_detected_at: null,
    effective_since: "2026-04-01T00:00:00Z",
    effective_until: "2026-04-21T00:00:00Z",
  });
}

function handleScansList(url: URL, res: ServerResponse): void {
  const tenantId = url.searchParams.get("tenant_id");
  const offset = Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0;
  const limit = Number.parseInt(url.searchParams.get("limit") ?? "25", 10) || 25;

  // Without a tenant filter we still return the full set so the page
  // renders rows for the a11y suite. Production routing layer enforces
  // tenant filtering.
  const items = tenantId
    ? SCANS.filter(
        (s) =>
          (s as Record<string, JsonValue>)["id"] !== "ignore" &&
          tenantId.length > 0,
      )
    : SCANS.slice();
  writeJson(res, 200, {
    scans: items.slice(offset, offset + limit),
    total: items.length,
    limit,
    offset,
  });
}

function handleScanDetail(scanId: string, res: ServerResponse): void {
  if (scanId !== MOCK_SCAN_ID) {
    writeNotFound(res);
    return;
  }
  writeJson(res, 200, SCAN_DETAIL);
}

function handleTenants(res: ServerResponse): void {
  writeJson(res, 200, TENANTS);
}

async function dispatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = parseUrl(req);
  const method = (req.method ?? "GET").toUpperCase();
  const path = url.pathname;

  // OPTIONS preflight — Next.js server-to-server fetches don't issue
  // these, but the dev hot-reload sometimes does for client probes.
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key, X-Admin-Role, X-Admin-Tenant, X-Operator-Subject",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
    });
    res.end();
    return;
  }

  if (path === "/api/v1/admin/findings" && method === "GET") {
    handleFindings(url, res);
    return;
  }

  if (path === "/api/v1/admin/findings/bulk-suppress" && method === "POST") {
    const body = await readBody(req);
    handleBulkSuppress(body, res);
    return;
  }

  if (path === "/api/v1/admin/audit-logs" && method === "GET") {
    handleAuditLogs(url, res);
    return;
  }

  if (path === "/api/v1/admin/audit-logs/verify-chain" && method === "POST") {
    handleVerifyChain(res);
    return;
  }

  if (path === "/api/v1/admin/tenants" && method === "GET") {
    handleTenants(res);
    return;
  }

  if (path === "/api/v1/admin/scans" && method === "GET") {
    handleScansList(url, res);
    return;
  }

  const scanDetailMatch = path.match(/^\/api\/v1\/admin\/scans\/([^/]+)$/);
  if (scanDetailMatch && method === "GET") {
    handleScanDetail(scanDetailMatch[1], res);
    return;
  }

  // Fall-through — keep the body small so axe never sees a giant 404
  // body in any pages that surface the raw response.
  writeNotFound(res);
}

export type AdminBackendMock = {
  readonly url: string;
  readonly stop: () => Promise<void>;
};

/**
 * Starts the mock on a free loopback port and resolves with `{url, stop}`.
 *
 * We deliberately bind to `127.0.0.1` (not `0.0.0.0`) so the server is
 * unreachable from outside the test container even if the port were
 * accidentally published.
 */
export async function startAdminBackendMock(
  port: number,
): Promise<AdminBackendMock> {
  const server: Server = createServer((req, res) => {
    dispatch(req, res).catch((err) => {
      // Defensive: unhandled exceptions shouldn't crash the test run.
      const message =
        err instanceof Error ? err.message : "internal_error";
      writeJson(res, 500, { detail: message });
    });
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => {
      server.removeListener("listening", onListening);
      reject(err);
    };
    const onListening = () => {
      server.removeListener("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, "127.0.0.1");
  });

  const address = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${address.port}`;

  return {
    url,
    stop: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

export const ADMIN_BACKEND_MOCK_PORT = 8902;
export const ADMIN_BACKEND_MOCK_KEY = "test-a11y-admin-key";
export const MOCK_TENANT_PRIMARY = MOCK_TENANT_ID;
export const MOCK_TENANT_SECONDARY = MOCK_SECONDARY_TENANT_ID;
export const MOCK_SCAN_PRIMARY = MOCK_SCAN_ID;
