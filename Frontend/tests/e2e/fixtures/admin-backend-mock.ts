/**
 * Stand-alone mock of the FastAPI `/api/v1/admin/*` surface used by the
 * Playwright accessibility (T26) and functional (T27) E2E suites.
 *
 * Why a real HTTP server, not `page.route()`:
 *   The admin pages call FastAPI from Next.js Server Actions running on the
 *   Node side, NOT from the browser. `page.route()` would never see those
 *   requests. Instead we point the dev server's `BACKEND_URL` env at this
 *   mock and let the actions hit a real (loopback) HTTP listener.
 *
 * Test-control query parameters (only honoured by this mock; the real
 * FastAPI router rejects unknown query keys):
 *   - `?_test_drift=true` on `POST /admin/audit-logs/verify-chain` flips
 *     the verdict to `ok: false` and points `drift_event_id` at a known
 *     entry so T27's drift scenarios can assert the red-banner UX.
 *   - `?_test_partial=true` on `POST /admin/findings/bulk-suppress`
 *     marks ~half of the requested ids as `not_found` so the partial-
 *     failure banner branch is reachable from a deterministic test.
 *   - `?_test_export_disabled=true` on `GET /admin/scans` returns the
 *     scan with `exports_sarif_junit_enabled: false` to assert the
 *     toggle's disabled state (T23 RBAC variant).
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
const MOCK_SCAN_SECONDARY_ID = "22222222-3333-4444-5555-666666666666";
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

/**
 * Synthetic findings spanning both mock tenants and all five severity buckets
 * so T27 can exercise pagination, severity filters, and cross-tenant rendering
 * deterministically. Eight rows total: 4 in the primary tenant (1 critical +
 * 1 high + 1 medium + 1 low) and 4 in the secondary tenant (1 critical + 1
 * high + 1 medium + 1 info).
 */
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
    scan_id: MOCK_SCAN_SECONDARY_ID,
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
  {
    id: "f0000004-0000-0000-0000-000000000004",
    tenant_id: MOCK_TENANT_ID,
    scan_id: MOCK_SCAN_ID,
    severity: "medium",
    title: "Cookie missing Secure flag on session",
    status: "open",
    target: "https://app.example.com/login",
    cve_ids: [],
    cvss: 4.2,
    cvss_score: 4.2,
    epss_score: 0.05,
    kev_listed: false,
    ssvc_action: "track",
    discovered_at: "2026-04-17T11:00:00Z",
    updated_at: "2026-04-17T11:00:00Z",
    created_at: "2026-04-17T11:00:00Z",
  },
  {
    id: "f0000005-0000-0000-0000-000000000005",
    tenant_id: MOCK_TENANT_ID,
    scan_id: MOCK_SCAN_ID,
    severity: "low",
    title: "Verbose error page leaks framework version",
    status: "open",
    target: "https://api.example.com/status",
    cve_ids: [],
    cvss: 2.5,
    cvss_score: 2.5,
    epss_score: 0.01,
    kev_listed: false,
    ssvc_action: "track",
    discovered_at: "2026-04-17T13:30:00Z",
    updated_at: "2026-04-17T13:30:00Z",
    created_at: "2026-04-17T13:30:00Z",
  },
  {
    id: "f0000006-0000-0000-0000-000000000006",
    tenant_id: MOCK_SECONDARY_TENANT_ID,
    scan_id: MOCK_SCAN_SECONDARY_ID,
    severity: "critical",
    title: "Default admin credentials accepted on /admin",
    status: "open",
    target: "https://internal.example.com/admin",
    cve_ids: ["CVE-2025-00001"],
    cvss: 9.8,
    cvss_score: 9.8,
    epss_score: 0.65,
    kev_listed: true,
    ssvc_action: "act",
    discovered_at: "2026-04-18T08:00:00Z",
    updated_at: "2026-04-18T08:00:00Z",
    created_at: "2026-04-18T08:00:00Z",
  },
  {
    id: "f0000007-0000-0000-0000-000000000007",
    tenant_id: MOCK_SECONDARY_TENANT_ID,
    scan_id: MOCK_SCAN_SECONDARY_ID,
    severity: "high",
    title: "SQL injection on /api/products",
    status: "open",
    target: "https://api.example.com/products",
    cve_ids: [],
    cvss: 8.1,
    cvss_score: 8.1,
    epss_score: 0.32,
    kev_listed: false,
    ssvc_action: "attend",
    discovered_at: "2026-04-18T09:15:00Z",
    updated_at: "2026-04-18T09:15:00Z",
    created_at: "2026-04-18T09:15:00Z",
  },
  {
    id: "f0000008-0000-0000-0000-000000000008",
    tenant_id: MOCK_SECONDARY_TENANT_ID,
    scan_id: MOCK_SCAN_SECONDARY_ID,
    severity: "info",
    title: "Server header discloses Apache 2.4",
    status: "open",
    target: "https://web.example.com",
    cve_ids: [],
    cvss: 0,
    cvss_score: 0,
    epss_score: 0,
    kev_listed: false,
    ssvc_action: "track",
    discovered_at: "2026-04-18T10:00:00Z",
    updated_at: "2026-04-18T10:00:00Z",
    created_at: "2026-04-18T10:00:00Z",
  },
];

/**
 * Audit-log entries. Each row carries chain markers (`_event_hash` /
 * `_prev_event_hash`) inside `details` so the AuditLogsTable renders
 * the chain badge — that is the cue T27's chain-aware tests look for.
 * The drift scenario points at `MOCK_AUDIT_DRIFT_ID` which is also in
 * this list, so the "scroll to drift record" affordance has a real row
 * to anchor to.
 */
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
    details: {
      source: "admin-console",
      scan_mode: "fast",
      _event_hash:
        "11111111111111111111111111111111111111111111111111111111aaaaaaaa",
      _prev_event_hash: null,
    },
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
    details: {
      reason: "duplicate",
      count: 1,
      _event_hash:
        "22222222222222222222222222222222222222222222222222222222bbbbbbbb",
      _prev_event_hash:
        "11111111111111111111111111111111111111111111111111111111aaaaaaaa",
    },
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
    details: {
      window: "2026-04-19/2026-04-20",
      _event_hash:
        "33333333333333333333333333333333333333333333333333333333cccccccc",
      _prev_event_hash:
        "22222222222222222222222222222222222222222222222222222222bbbbbbbb",
    },
    severity: "info",
  },
  {
    id: "ev0000004-0000-0000-0000-000000000004",
    created_at: "2026-04-20T09:00:00Z",
    event_type: "tenant.updated",
    action: "tenant.updated",
    actor_subject: "admin_console:super-admin",
    user_id: null,
    tenant_id: MOCK_SECONDARY_TENANT_ID,
    resource_type: "tenant",
    resource_id: MOCK_SECONDARY_TENANT_ID,
    details: {
      field: "rate_limit_rpm",
      _event_hash:
        "44444444444444444444444444444444444444444444444444444444dddddddd",
      _prev_event_hash:
        "33333333333333333333333333333333333333333333333333333333cccccccc",
    },
    severity: "info",
  },
];

const SCANS: JsonValue[] = [
  {
    id: MOCK_SCAN_ID,
    tenant_id: MOCK_TENANT_ID,
    status: "completed",
    progress: 100,
    phase: "done",
    target: "https://api.example.com",
    created_at: "2026-04-15T09:00:00Z",
    updated_at: "2026-04-15T09:30:00Z",
    scan_mode: "fast",
  },
  {
    id: MOCK_SCAN_SECONDARY_ID,
    tenant_id: MOCK_TENANT_ID,
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

/**
 * Minimal SARIF 2.1.0 envelope returned by the mock export endpoint.
 * Keeps the body small so axe / Playwright never has to parse a giant
 * binary blob; the contract under test is "the format toggle drives the
 * URL we hit and the file download triggers", not SARIF correctness.
 */
const SARIF_BODY: JsonValue = {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "argus", version: "test" } },
      results: [
        {
          ruleId: "T27-MOCK-001",
          message: { text: "Mocked SARIF result" },
          level: "warning",
        },
      ],
    },
  ],
};

const JUNIT_XML = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="argus-mock">
  <testsuite name="findings" tests="1" failures="1">
    <testcase classname="argus" name="T27-MOCK-001">
      <failure message="Mocked JUnit failure" type="WARN"/>
    </testcase>
  </testsuite>
</testsuites>
`;

function writeJson(res: ServerResponse, status: number, body: JsonValue): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(text).toString(),
  });
  res.end(text);
}

function writeText(
  res: ServerResponse,
  status: number,
  contentType: string,
  body: string,
): void {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": Buffer.byteLength(body).toString(),
  });
  res.end(body);
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

function asRecord(value: JsonValue): Record<string, JsonValue> {
  // FINDINGS / AUDIT_LOGS are object literals in the source — narrowing
  // through `Record<string, JsonValue>` keeps the rest of the dispatcher
  // free of `as any` casts.
  return value as Record<string, JsonValue>;
}

function handleFindings(url: URL, res: ServerResponse): void {
  const tenantFilter = url.searchParams.get("tenant_id");
  const severityFilter = url.searchParams.getAll("severity");
  const offset = Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0;
  const limit = Number.parseInt(url.searchParams.get("limit") ?? "50", 10) || 50;
  const q = url.searchParams.get("q")?.trim().toLowerCase() ?? "";

  let items = FINDINGS.slice();
  if (tenantFilter) {
    items = items.filter(
      (item) => asRecord(item)["tenant_id"] === tenantFilter,
    );
  }
  if (severityFilter.length > 0) {
    const allowed = new Set(severityFilter);
    items = items.filter((item) => allowed.has(String(asRecord(item)["severity"])));
  }
  if (q) {
    items = items.filter((item) => {
      const r = asRecord(item);
      const title = String(r["title"] ?? "").toLowerCase();
      const target = String(r["target"] ?? "").toLowerCase();
      return title.includes(q) || target.includes(q);
    });
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

/**
 * Bulk-suppress mock. Honours `?_test_partial=true` to mark the second
 * half of the requested ids as `not_found` so T27 can deterministically
 * exercise the partial-failure banner branch in `AdminFindingsClient`.
 */
function handleBulkSuppress(
  url: URL,
  body: string,
  res: ServerResponse,
): void {
  let parsed: { tenant_id?: string; finding_ids?: string[]; reason?: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }
  const ids = Array.isArray(parsed.finding_ids) ? parsed.finding_ids : [];
  const partial = url.searchParams.get("_test_partial") === "true";

  if (partial && ids.length > 0) {
    const half = Math.max(1, Math.floor(ids.length / 2));
    const suppressedIds = ids.slice(0, half);
    const notFoundIds = ids.slice(half);
    writeJson(res, 200, {
      suppressed_count: suppressedIds.length,
      skipped_already_suppressed_count: 0,
      not_found_count: notFoundIds.length,
      audit_id: "ev_bulk_suppress_partial",
      results: [
        ...suppressedIds.map((id) => ({
          finding_id: id,
          status: "suppressed",
        })),
        ...notFoundIds.map((id) => ({
          finding_id: id,
          status: "not_found",
        })),
      ],
    });
    return;
  }

  writeJson(res, 200, {
    suppressed_count: ids.length,
    skipped_already_suppressed_count: 0,
    not_found_count: 0,
    audit_id: "ev_bulk_suppress_test",
    results: ids.map((id) => ({ finding_id: id, status: "suppressed" })),
  });
}

function handleAuditLogs(url: URL, res: ServerResponse): void {
  const tenantFilter = url.searchParams.get("tenant_id");
  const eventType = url.searchParams.get("event_type");
  const q = url.searchParams.get("q")?.trim().toLowerCase() ?? "";
  const limit = Number.parseInt(url.searchParams.get("limit") ?? "50", 10) || 50;
  const offset = Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0;

  let items = AUDIT_LOGS.slice();
  if (tenantFilter) {
    items = items.filter((item) => asRecord(item)["tenant_id"] === tenantFilter);
  }
  if (eventType) {
    items = items.filter((item) => asRecord(item)["event_type"] === eventType);
  }
  if (q) {
    items = items.filter((item) => {
      const r = asRecord(item);
      const action = String(r["action"] ?? "").toLowerCase();
      const resourceType = String(r["resource_type"] ?? "").toLowerCase();
      return action.includes(q) || resourceType.includes(q);
    });
  }
  const sliced = items.slice(offset, offset + limit);
  // Wrapped envelope shape — mirrors the post-T22 backend; the schema
  // accepts the bare-array form too, but the wrapped form lets us return
  // an accurate `total` to drive the page counter.
  writeJson(res, 200, {
    items: sliced,
    total: items.length,
    next_cursor: null,
  });
}

/**
 * Chain verify mock. Honours `?_test_drift=true` to flip the verdict to
 * a drift response pointing at `MOCK_AUDIT_DRIFT_ID` so T27's red-banner
 * scenarios can assert the drift UX without a real chain ledger.
 */
/**
 * Trigger value the E2E suite uses to make the chain-verify endpoint
 * return a DRIFT verdict. Plumbed through `event_type` because that is
 * the only knob the UI's verify-chain mutation actually forwards to
 * the backend (see `audit-logs/actions.ts::buildVerifyQuery`).
 *
 * Production audit events would never carry this `event_type` value, so
 * leaking the trigger to a real backend would simply return zero rows.
 * Making the trigger reachable via a filter keeps test wiring out of the
 * production code path entirely.
 */
const VERIFY_DRIFT_TRIGGER = "_t27_drift";

function handleVerifyChain(url: URL, res: ServerResponse): void {
  const eventType = url.searchParams.get("event_type") ?? "";
  const drift =
    eventType === VERIFY_DRIFT_TRIGGER ||
    url.searchParams.get("_test_drift") === "true";
  if (drift) {
    writeJson(res, 200, {
      ok: false,
      verified_count: 1,
      last_verified_index: 1,
      drift_event_id: MOCK_AUDIT_DRIFT_ID,
      drift_detected_at: "2026-04-20T08:11:00Z",
      effective_since: "2026-04-01T00:00:00Z",
      effective_until: "2026-04-21T00:00:00Z",
    });
    return;
  }
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

  const items = tenantId
    ? SCANS.filter((s) => asRecord(s)["tenant_id"] === tenantId)
    : SCANS.slice();
  writeJson(res, 200, {
    scans: items.slice(offset, offset + limit),
    total: items.length,
    limit,
    offset,
  });
}

function handleScanDetail(scanId: string, res: ServerResponse): void {
  if (scanId === MOCK_SCAN_ID) {
    writeJson(res, 200, SCAN_DETAIL);
    return;
  }
  if (scanId === MOCK_SCAN_SECONDARY_ID) {
    // Mirror the secondary entry in `SCANS` and reuse the primary's
    // tool/error shapes so the drawer renders identically. Avoids
    // duplicating the entire object literal twice.
    const primary = asRecord(SCAN_DETAIL);
    writeJson(res, 200, {
      ...primary,
      id: MOCK_SCAN_SECONDARY_ID,
      status: "running",
      progress: 42,
      phase: "exploit",
      target: "https://web.example.com",
      created_at: "2026-04-19T12:00:00Z",
      updated_at: "2026-04-19T12:15:00Z",
      scan_mode: "deep",
    });
    return;
  }
  writeNotFound(res);
}

function handleTenants(res: ServerResponse): void {
  writeJson(res, 200, TENANTS);
}

/**
 * Findings export endpoint. The real backend dispatches on the `format`
 * query param and returns SARIF JSON or JUnit XML. The mock returns a
 * minimal but valid-looking document so the browser-side blob/anchor
 * dance succeeds and Playwright can observe the resulting download.
 */
function handleFindingsExport(
  scanId: string,
  url: URL,
  res: ServerResponse,
): void {
  if (scanId !== MOCK_SCAN_ID && scanId !== MOCK_SCAN_SECONDARY_ID) {
    writeNotFound(res);
    return;
  }
  const fmt = url.searchParams.get("format");
  if (fmt === "junit") {
    writeText(res, 200, "application/xml; charset=utf-8", JUNIT_XML);
    return;
  }
  if (fmt === "sarif") {
    const text = JSON.stringify(SARIF_BODY);
    res.writeHead(200, {
      "Content-Type": "application/sarif+json; charset=utf-8",
      "Content-Length": Buffer.byteLength(text).toString(),
    });
    res.end(text);
    return;
  }
  writeJson(res, 400, { detail: "invalid_format" });
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
    handleBulkSuppress(url, body, res);
    return;
  }

  if (path === "/api/v1/admin/audit-logs" && method === "GET") {
    handleAuditLogs(url, res);
    return;
  }

  if (path === "/api/v1/admin/audit-logs/verify-chain" && method === "POST") {
    handleVerifyChain(url, res);
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

  // T23 export endpoint — note this lives under `/api/v1/scans/...`,
  // NOT `/api/v1/admin/scans/...` (matches the real router layout in
  // `backend/src/api/routers/scans.py::export_scan_findings`).
  const exportMatch = path.match(
    /^\/api\/v1\/scans\/([^/]+)\/findings\/export$/,
  );
  if (exportMatch && method === "GET") {
    handleFindingsExport(exportMatch[1], url, res);
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
export const MOCK_SCAN_SECONDARY = MOCK_SCAN_SECONDARY_ID;
export const MOCK_AUDIT_DRIFT_EVENT_ID = MOCK_AUDIT_DRIFT_ID;

/**
 * Stable, public-by-design ids for the synthetic data the mock seeds.
 * Tests import these instead of hard-coding ids inline so a future
 * dataset change ripples through one place only.
 */
export const MOCK_FINDINGS_IDS = {
  primaryCritical: "f0000001-0000-0000-0000-000000000001",
  primaryHigh: "f0000002-0000-0000-0000-000000000002",
  secondaryMedium: "f0000003-0000-0000-0000-000000000003",
  primaryMedium: "f0000004-0000-0000-0000-000000000004",
  primaryLow: "f0000005-0000-0000-0000-000000000005",
  secondaryCritical: "f0000006-0000-0000-0000-000000000006",
  secondaryHigh: "f0000007-0000-0000-0000-000000000007",
  secondaryInfo: "f0000008-0000-0000-0000-000000000008",
} as const;
