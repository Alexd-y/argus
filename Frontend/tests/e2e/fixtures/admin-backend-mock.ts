/**
 * Stand-alone mock of the FastAPI `/api/v1/admin/*` surface used by the
 * Playwright accessibility (T26) and functional (T27, T36) E2E suites.
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
 *   - A schedule whose `maintenance_window_cron === "* * * * *"` is
 *     treated as always-in-window so a Run-Now without bypass returns
 *     409 deterministically without dragging a real cron-parser into
 *     the mock.
 *   - `?_test_in_maintenance=true` on `POST /admin/scan-schedules/{id}/
 *     run-now` returns 409 + `detail: "in_maintenance_window"` so T36
 *     can deterministically exercise the "bypass" toast branch without
 *     racing the wall clock.
 *   - `?_test_emergency_active=true` on the same endpoint returns 409 +
 *     `detail: "emergency_active"` so T36 can assert the global-
 *     kill-switch interlock from the schedules surface.
 *   - `?_test_name_conflict=true` on `POST /admin/scan-schedules` returns
 *     409 + `detail: "schedule_name_conflict"` regardless of the actual
 *     in-memory state so T36 can exercise the editor's error mapping.
 *   - T41 webhook DLQ (admin/webhooks/dlq) — sentinel entry ids deterministically
 *     trigger every member of `WEBHOOK_DLQ_FAILURE_TAXONOMY`:
 *       - 11111111-aaaa-bbbb-cccc-000000000001 → 404 dlq_entry_not_found
 *       - 11111111-aaaa-bbbb-cccc-000000000002 → 409 already_replayed
 *       - 11111111-aaaa-bbbb-cccc-000000000003 → 409 already_abandoned
 *       - 11111111-aaaa-bbbb-cccc-000000000004 → 202 success=false (replay_failed)
 *       - 11111111-aaaa-bbbb-cccc-000000000005 → 422 validation_failed
 *       - 11111111-aaaa-bbbb-cccc-000000000006 → 500 server_error
 *       - 11111111-aaaa-bbbb-cccc-000000000007 → 503 store_unavailable
 *       - 11111111-aaaa-bbbb-cccc-000000000008 → 403 forbidden
 *       - any other UUID → success path
 *
 * Mock-only control endpoint (NOT served by real FastAPI):
 *   - `POST /api/v1/__test__/reset` clears the per-suite in-memory state
 *     (kill-switch flag, throttles, schedules, emergency audit log) so
 *     each spec starts from the same seed. The real production router
 *     does not expose `/api/v1/__test__/*` — leaking a call here against
 *     a real backend simply 404s and is therefore harmless.
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

/**
 * `SCANS` is mutable because T36 fires `bulk-cancel` against the running
 * row (status: "running" → "cancelled") and asserts the badge flip on
 * reload. The reset endpoint reseeds it from `SCANS_SEED` so each spec
 * gets the same starting state regardless of order.
 */
const SCANS_SEED: ReadonlyArray<JsonValue> = [
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

let SCANS: JsonValue[] = SCANS_SEED.map((s) => ({ ...asRecord(s) }));

// ──────────────────────────────────────────────────────────────────────
// T36 mock state — emergency surface (kill-switch, throttles, audit) +
// scan schedules. All reseeded by `POST /api/v1/__test__/reset`.
// ──────────────────────────────────────────────────────────────────────

const MOCK_SCHEDULE_PRIMARY_ID = "55555555-aaaa-bbbb-cccc-111111111111";
const MOCK_SCHEDULE_MAINT_ID = "55555555-aaaa-bbbb-cccc-222222222222";
const MOCK_SCHEDULE_SECONDARY_ID = "55555555-aaaa-bbbb-cccc-333333333333";

type ScheduleRow = {
  id: string;
  tenant_id: string;
  name: string;
  cron_expression: string;
  target_url: string;
  scan_mode: string;
  enabled: boolean;
  maintenance_window_cron: string | null;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
  updated_at: string;
};

const SCHEDULES_SEED: ReadonlyArray<ScheduleRow> = [
  {
    id: MOCK_SCHEDULE_PRIMARY_ID,
    tenant_id: MOCK_TENANT_ID,
    name: "Nightly api scan",
    cron_expression: "0 2 * * *",
    target_url: "https://api.example.com",
    scan_mode: "standard",
    enabled: true,
    maintenance_window_cron: null,
    last_run_at: "2026-04-21T02:00:00Z",
    next_run_at: "2026-04-22T02:00:00Z",
    created_at: "2026-03-01T00:00:00Z",
    updated_at: "2026-04-21T02:00:00Z",
  },
  {
    id: MOCK_SCHEDULE_MAINT_ID,
    tenant_id: MOCK_TENANT_ID,
    name: "Hourly internal probe",
    cron_expression: "0 * * * *",
    target_url: "https://web.example.com",
    scan_mode: "standard",
    enabled: false,
    maintenance_window_cron: "0 22 * * *",
    last_run_at: null,
    next_run_at: null,
    created_at: "2026-04-10T00:00:00Z",
    updated_at: "2026-04-10T00:00:00Z",
  },
  {
    id: MOCK_SCHEDULE_SECONDARY_ID,
    tenant_id: MOCK_SECONDARY_TENANT_ID,
    name: "Beta tenant cron",
    cron_expression: "30 6 * * *",
    target_url: "https://internal.example.com",
    scan_mode: "deep",
    enabled: true,
    maintenance_window_cron: null,
    last_run_at: null,
    next_run_at: "2026-04-22T06:30:00Z",
    created_at: "2026-04-12T00:00:00Z",
    updated_at: "2026-04-12T00:00:00Z",
  },
];

// ──────────────────────────────────────────────────────────────────────
// T41 — webhook DLQ seed data + sentinel ids.
// Each sentinel id deterministically triggers a single error code from
// `WEBHOOK_DLQ_FAILURE_TAXONOMY` so the Playwright + Vitest suites can
// exercise every branch without timing-dependent mocks.
// ──────────────────────────────────────────────────────────────────────

const DLQ_SENTINEL_NOT_FOUND = "11111111-aaaa-bbbb-cccc-000000000001";
const DLQ_SENTINEL_ALREADY_REPLAYED = "11111111-aaaa-bbbb-cccc-000000000002";
const DLQ_SENTINEL_ALREADY_ABANDONED = "11111111-aaaa-bbbb-cccc-000000000003";
const DLQ_SENTINEL_REPLAY_FAILED = "11111111-aaaa-bbbb-cccc-000000000004";
const DLQ_SENTINEL_VALIDATION = "11111111-aaaa-bbbb-cccc-000000000005";
const DLQ_SENTINEL_SERVER_ERROR = "11111111-aaaa-bbbb-cccc-000000000006";
const DLQ_SENTINEL_STORE_UNAVAILABLE = "11111111-aaaa-bbbb-cccc-000000000007";
const DLQ_SENTINEL_FORBIDDEN = "11111111-aaaa-bbbb-cccc-000000000008";

type DlqRow = {
  id: string;
  tenant_id: string;
  adapter_name: string;
  event_type: string;
  event_id: string;
  target_url_hash: string;
  attempt_count: number;
  last_error_code: string;
  last_status_code: number | null;
  next_retry_at: string | null;
  created_at: string;
  replayed_at: string | null;
  abandoned_at: string | null;
  abandoned_reason: string | null;
};

const DLQ_SEED: ReadonlyArray<DlqRow> = [
  {
    id: DLQ_SENTINEL_NOT_FOUND,
    tenant_id: MOCK_TENANT_ID,
    adapter_name: "slack",
    event_type: "scan.completed",
    event_id: "evt_dlq_not_found_0001",
    target_url_hash:
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    attempt_count: 5,
    last_error_code: "http_502",
    last_status_code: 502,
    next_retry_at: null,
    created_at: "2026-04-20T08:00:00Z",
    replayed_at: null,
    abandoned_at: null,
    abandoned_reason: null,
  },
  {
    id: DLQ_SENTINEL_ALREADY_REPLAYED,
    tenant_id: MOCK_TENANT_ID,
    adapter_name: "linear",
    event_type: "finding.created",
    event_id: "evt_dlq_already_replay_0002",
    target_url_hash:
      "1023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    attempt_count: 3,
    last_error_code: "http_500",
    last_status_code: 500,
    next_retry_at: null,
    created_at: "2026-04-20T09:00:00Z",
    replayed_at: "2026-04-21T10:00:00Z",
    abandoned_at: null,
    abandoned_reason: null,
  },
  {
    id: DLQ_SENTINEL_ALREADY_ABANDONED,
    tenant_id: MOCK_TENANT_ID,
    adapter_name: "jira",
    event_type: "finding.suppressed",
    event_id: "evt_dlq_already_abandon_0003",
    target_url_hash:
      "2023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    attempt_count: 7,
    last_error_code: "http_403",
    last_status_code: 403,
    next_retry_at: null,
    created_at: "2026-04-20T10:00:00Z",
    replayed_at: null,
    abandoned_at: "2026-04-21T11:00:00Z",
    abandoned_reason: "operator",
  },
  {
    id: DLQ_SENTINEL_REPLAY_FAILED,
    tenant_id: MOCK_TENANT_ID,
    adapter_name: "slack",
    event_type: "scan.completed",
    event_id: "evt_dlq_replay_fail_0004",
    target_url_hash:
      "3023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    attempt_count: 2,
    last_error_code: "timeout",
    last_status_code: null,
    next_retry_at: null,
    created_at: "2026-04-20T11:00:00Z",
    replayed_at: null,
    abandoned_at: null,
    abandoned_reason: null,
  },
  {
    id: DLQ_SENTINEL_VALIDATION,
    tenant_id: MOCK_TENANT_ID,
    adapter_name: "linear",
    event_type: "finding.created",
    event_id: "evt_dlq_validation_0005",
    target_url_hash:
      "4023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    attempt_count: 1,
    last_error_code: "http_400",
    last_status_code: 400,
    next_retry_at: null,
    created_at: "2026-04-20T12:00:00Z",
    replayed_at: null,
    abandoned_at: null,
    abandoned_reason: null,
  },
  {
    id: DLQ_SENTINEL_SERVER_ERROR,
    tenant_id: MOCK_TENANT_ID,
    adapter_name: "jira",
    event_type: "scan.failed",
    event_id: "evt_dlq_server_err_0006",
    target_url_hash:
      "5023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    attempt_count: 4,
    last_error_code: "http_500",
    last_status_code: 500,
    next_retry_at: null,
    created_at: "2026-04-20T13:00:00Z",
    replayed_at: null,
    abandoned_at: null,
    abandoned_reason: null,
  },
  {
    id: DLQ_SENTINEL_STORE_UNAVAILABLE,
    tenant_id: MOCK_TENANT_ID,
    adapter_name: "slack",
    event_type: "scan.started",
    event_id: "evt_dlq_store_unav_0007",
    target_url_hash:
      "6023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    attempt_count: 6,
    last_error_code: "connection_reset",
    last_status_code: null,
    next_retry_at: null,
    created_at: "2026-04-20T14:00:00Z",
    replayed_at: null,
    abandoned_at: null,
    abandoned_reason: null,
  },
  {
    id: DLQ_SENTINEL_FORBIDDEN,
    tenant_id: MOCK_SECONDARY_TENANT_ID,
    adapter_name: "linear",
    event_type: "tenant.created",
    event_id: "evt_dlq_forbidden_0008",
    target_url_hash:
      "7023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    attempt_count: 8,
    last_error_code: "http_403",
    last_status_code: 403,
    next_retry_at: null,
    created_at: "2026-04-20T15:00:00Z",
    replayed_at: null,
    abandoned_at: null,
    abandoned_reason: null,
  },
];

type ThrottleRow = {
  tenant_id: string;
  reason: string;
  activated_at: string;
  expires_at: string;
  duration_seconds: number;
};

type EmergencyAuditRow = {
  audit_id: string;
  event_type: "emergency.stop_all" | "emergency.resume_all" | "emergency.throttle";
  tenant_id_hash: string;
  operator_subject_hash: string | null;
  reason: string | null;
  details: Record<string, JsonValue> | null;
  created_at: string;
};

type MockState = {
  killSwitchActive: boolean;
  killSwitchReason: string | null;
  killSwitchActivatedAt: string | null;
  throttles: ThrottleRow[];
  schedules: ScheduleRow[];
  emergencyAudit: EmergencyAuditRow[];
  auditCounter: number;
  dlqEntries: DlqRow[];
};

function freshState(): MockState {
  return {
    killSwitchActive: false,
    killSwitchReason: null,
    killSwitchActivatedAt: null,
    throttles: [],
    schedules: SCHEDULES_SEED.map((s) => ({ ...s })),
    emergencyAudit: [],
    auditCounter: 0,
    dlqEntries: DLQ_SEED.map((e) => ({ ...e })),
  };
}

let mockState: MockState = freshState();

function resetMockState(): void {
  mockState = freshState();
  SCANS = SCANS_SEED.map((s) => ({ ...asRecord(s) }));
}

/**
 * Deterministic 16-char hex hash for synthetic data. Mirrors the shape
 * of the backend `_hash_actor` helper (BLAKE2b(8 bytes) → 16 hex chars)
 * so the frontend Zod schemas accept it without modification.
 */
function fakeHash(prefix: string, value: string): string {
  let acc = 0;
  for (let i = 0; i < value.length; i++) {
    acc = (acc * 31 + value.charCodeAt(i)) >>> 0;
  }
  const head = prefix.padEnd(4, "0").slice(0, 4);
  const body = acc.toString(16).padStart(8, "0").slice(0, 8);
  return `${head}${body}${"abcdef01".slice(0, 4)}`;
}

function nextAuditId(): string {
  mockState.auditCounter += 1;
  const counter = mockState.auditCounter.toString(16).padStart(12, "0");
  return `00000000-0000-0000-0000-${counter}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

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

// ──────────────────────────────────────────────────────────────────────
// T36 — bulk-cancel (per-scan kill-switch funnels through this).
// ──────────────────────────────────────────────────────────────────────

function handleBulkScanCancel(body: string, res: ServerResponse): void {
  let parsed: { tenant_id?: string; scan_ids?: string[] };
  try {
    parsed = JSON.parse(body);
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }
  const tenantId = parsed.tenant_id ?? "";
  const ids = Array.isArray(parsed.scan_ids) ? parsed.scan_ids : [];
  if (!tenantId || ids.length === 0) {
    writeJson(res, 422, { detail: "validation_failed" });
    return;
  }

  let cancelled = 0;
  let skippedTerminal = 0;
  let notFound = 0;
  const results: Array<{ scan_id: string; status: string }> = [];

  for (const id of ids) {
    const idx = SCANS.findIndex(
      (s) =>
        asRecord(s)["id"] === id &&
        asRecord(s)["tenant_id"] === tenantId,
    );
    if (idx < 0) {
      notFound += 1;
      results.push({ scan_id: id, status: "not_found" });
      continue;
    }
    const row = asRecord(SCANS[idx]);
    const currentStatus = String(row["status"]);
    if (currentStatus === "completed" || currentStatus === "cancelled" || currentStatus === "failed") {
      skippedTerminal += 1;
      results.push({ scan_id: id, status: "skipped_terminal" });
      continue;
    }
    SCANS[idx] = {
      ...row,
      status: "cancelled",
      updated_at: nowIso(),
    };
    cancelled += 1;
    results.push({ scan_id: id, status: "cancelled" });
  }

  writeJson(res, 202, {
    cancelled_count: cancelled,
    skipped_terminal_count: skippedTerminal,
    not_found_count: notFound,
    audit_id: nextAuditId(),
    results,
  });
}

// ──────────────────────────────────────────────────────────────────────
// T36 — emergency surface
// ──────────────────────────────────────────────────────────────────────

function buildGlobalState(): JsonValue {
  return {
    active: mockState.killSwitchActive,
    reason: mockState.killSwitchReason,
    activated_at: mockState.killSwitchActivatedAt,
  };
}

function buildTenantThrottlesView(tenantFilter: string | null): JsonValue {
  const view = tenantFilter
    ? mockState.throttles.filter((t) => t.tenant_id === tenantFilter)
    : mockState.throttles.slice();
  return view.map((t) => ({ ...t }));
}

function handleEmergencyStatus(url: URL, res: ServerResponse): void {
  const tenantFilter = url.searchParams.get("tenant_id");
  writeJson(res, 200, {
    global_state: buildGlobalState(),
    tenant_throttles: buildTenantThrottlesView(tenantFilter),
    queried_at: nowIso(),
  });
}

function handleEmergencyThrottle(body: string, res: ServerResponse): void {
  let parsed: { tenant_id?: string; duration_minutes?: number; reason?: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }
  const tenantId = parsed.tenant_id ?? "";
  const duration = Number(parsed.duration_minutes);
  const reason = (parsed.reason ?? "").trim();

  if (!tenantId || ![15, 60, 240, 1440].includes(duration) || reason.length < 10) {
    writeJson(res, 422, { detail: "validation_failed" });
    return;
  }

  if (mockState.killSwitchActive) {
    writeJson(res, 409, { detail: "emergency_already_active" });
    return;
  }

  // Tenant-not-found path: only the seeded tenants exist.
  if (
    tenantId !== MOCK_TENANT_ID &&
    tenantId !== MOCK_SECONDARY_TENANT_ID
  ) {
    writeJson(res, 404, { detail: "tenant_not_found" });
    return;
  }

  const activatedAt = nowIso();
  const expiresAt = new Date(Date.now() + duration * 60_000).toISOString();
  const throttle: ThrottleRow = {
    tenant_id: tenantId,
    reason,
    activated_at: activatedAt,
    expires_at: expiresAt,
    duration_seconds: duration * 60,
  };
  // Replace existing throttle for the same tenant rather than stacking.
  mockState.throttles = mockState.throttles
    .filter((t) => t.tenant_id !== tenantId)
    .concat(throttle);

  const auditId = nextAuditId();
  mockState.emergencyAudit.unshift({
    audit_id: auditId,
    event_type: "emergency.throttle",
    tenant_id_hash: fakeHash("ten_", tenantId),
    operator_subject_hash: fakeHash("op__", "throttle"),
    reason,
    details: { duration_minutes: duration },
    created_at: activatedAt,
  });

  writeJson(res, 200, {
    status: "throttled",
    tenant_id: tenantId,
    duration_minutes: duration,
    expires_at: expiresAt,
    audit_id: auditId,
  });
}

function handleEmergencyStopAll(body: string, res: ServerResponse): void {
  let parsed: { reason?: string; confirmation_phrase?: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }
  const reason = (parsed.reason ?? "").trim();
  if (parsed.confirmation_phrase !== "STOP ALL SCANS" || reason.length < 10) {
    writeJson(res, 422, { detail: "validation_failed" });
    return;
  }
  if (mockState.killSwitchActive) {
    writeJson(res, 409, { detail: "emergency_already_active" });
    return;
  }
  const activatedAt = nowIso();
  mockState.killSwitchActive = true;
  mockState.killSwitchReason = reason;
  mockState.killSwitchActivatedAt = activatedAt;

  // Cancel every running scan to mirror the backend behaviour.
  let cancelled = 0;
  let skipped = 0;
  const tenantsAffected = new Set<string>();
  for (let i = 0; i < SCANS.length; i++) {
    const row = asRecord(SCANS[i]);
    const currentStatus = String(row["status"]);
    if (
      currentStatus === "completed" ||
      currentStatus === "cancelled" ||
      currentStatus === "failed"
    ) {
      skipped += 1;
      continue;
    }
    SCANS[i] = { ...row, status: "cancelled", updated_at: activatedAt };
    cancelled += 1;
    tenantsAffected.add(String(row["tenant_id"]));
  }

  const auditId = nextAuditId();
  mockState.emergencyAudit.unshift({
    audit_id: auditId,
    event_type: "emergency.stop_all",
    tenant_id_hash: fakeHash("glb_", "global"),
    operator_subject_hash: fakeHash("op__", "stop_all"),
    reason,
    details: { cancelled, skipped, tenants_affected: tenantsAffected.size },
    created_at: activatedAt,
  });

  writeJson(res, 200, {
    status: "stopped",
    cancelled_count: cancelled,
    skipped_terminal_count: skipped,
    tenants_affected: tenantsAffected.size,
    activated_at: activatedAt,
    audit_id: auditId,
  });
}

function handleEmergencyResumeAll(body: string, res: ServerResponse): void {
  let parsed: { reason?: string; confirmation_phrase?: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }
  const reason = (parsed.reason ?? "").trim();
  if (parsed.confirmation_phrase !== "RESUME ALL SCANS" || reason.length < 10) {
    writeJson(res, 422, { detail: "validation_failed" });
    return;
  }
  if (!mockState.killSwitchActive) {
    writeJson(res, 409, { detail: "emergency_not_active" });
    return;
  }
  const resumedAt = nowIso();
  mockState.killSwitchActive = false;
  mockState.killSwitchReason = null;
  mockState.killSwitchActivatedAt = null;

  const auditId = nextAuditId();
  mockState.emergencyAudit.unshift({
    audit_id: auditId,
    event_type: "emergency.resume_all",
    tenant_id_hash: fakeHash("glb_", "global"),
    operator_subject_hash: fakeHash("op__", "resume_all"),
    reason,
    details: null,
    created_at: resumedAt,
  });

  writeJson(res, 200, {
    status: "resumed",
    resumed_at: resumedAt,
    audit_id: auditId,
  });
}

function handleEmergencyAuditTrail(url: URL, res: ServerResponse): void {
  const tenantFilter = url.searchParams.get("tenant_id");
  const limit = Math.min(
    200,
    Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "25", 10) || 25),
  );

  let items = mockState.emergencyAudit.slice();
  if (tenantFilter) {
    const wantedHash = fakeHash("ten_", tenantFilter);
    items = items.filter((row) => row.tenant_id_hash === wantedHash);
  }
  const sliced = items.slice(0, limit);
  writeJson(res, 200, {
    items: sliced,
    limit,
    has_more: items.length > sliced.length,
  });
}

// ──────────────────────────────────────────────────────────────────────
// T36 — scan schedules CRUD + run-now
// ──────────────────────────────────────────────────────────────────────

function buildScheduleResponse(row: ScheduleRow): JsonValue {
  return { ...row };
}

function handleSchedulesList(url: URL, res: ServerResponse): void {
  const tenantId = url.searchParams.get("tenant_id");
  const offset = Math.max(0, Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0);
  const limit = Math.min(
    200,
    Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "50", 10) || 50),
  );

  let items = mockState.schedules.slice();
  if (tenantId) {
    items = items.filter((s) => s.tenant_id === tenantId);
  }
  const sliced = items.slice(offset, offset + limit);
  writeJson(res, 200, {
    items: sliced.map(buildScheduleResponse),
    total: items.length,
    limit,
    offset,
  });
}

function handleScheduleCreate(url: URL, body: string, res: ServerResponse): void {
  if (mockState.killSwitchActive) {
    writeJson(res, 409, { detail: "emergency_active" });
    return;
  }
  if (url.searchParams.get("_test_name_conflict") === "true") {
    writeJson(res, 409, { detail: "schedule_name_conflict" });
    return;
  }
  let parsed: {
    tenant_id?: string;
    name?: string;
    cron_expression?: string;
    target_url?: string;
    scan_mode?: string;
    enabled?: boolean;
    maintenance_window_cron?: string | null;
  };
  try {
    parsed = JSON.parse(body);
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }
  const tenantId = parsed.tenant_id ?? "";
  const name = (parsed.name ?? "").trim();
  const cron = (parsed.cron_expression ?? "").trim();
  const target = (parsed.target_url ?? "").trim();
  const mode = parsed.scan_mode ?? "";

  if (!tenantId || !name || !cron || !target || !mode) {
    writeJson(res, 422, { detail: "validation_failed" });
    return;
  }
  // Synthetic cron sanity: the backend rejects expressions firing more
  // often than every 5 min. We only check the leading minute field for
  // the test-control case `"* * * * *"` to keep the mock small.
  if (cron === "* * * * *") {
    writeJson(res, 422, { detail: "invalid_cron_expression" });
    return;
  }
  // Real conflict check (in addition to the test-control flag above).
  const conflict = mockState.schedules.find(
    (s) => s.tenant_id === tenantId && s.name === name,
  );
  if (conflict) {
    writeJson(res, 409, { detail: "schedule_name_conflict" });
    return;
  }

  const createdAt = nowIso();
  const id = `${MOCK_SCHEDULE_PRIMARY_ID.slice(0, 24)}${(mockState.schedules.length + 100).toString(16).padStart(12, "0").slice(-12)}`;
  const row: ScheduleRow = {
    id,
    tenant_id: tenantId,
    name,
    cron_expression: cron,
    target_url: target,
    scan_mode: mode,
    enabled: parsed.enabled !== false,
    maintenance_window_cron:
      typeof parsed.maintenance_window_cron === "string" &&
      parsed.maintenance_window_cron.trim() !== ""
        ? parsed.maintenance_window_cron.trim()
        : null,
    last_run_at: null,
    next_run_at: null,
    created_at: createdAt,
    updated_at: createdAt,
  };
  mockState.schedules.push(row);
  writeJson(res, 201, buildScheduleResponse(row));
}

function findScheduleById(id: string): {
  index: number;
  row: ScheduleRow | null;
} {
  const idx = mockState.schedules.findIndex((s) => s.id === id);
  if (idx < 0) return { index: -1, row: null };
  return { index: idx, row: mockState.schedules[idx] };
}

function handleScheduleUpdate(
  scheduleId: string,
  body: string,
  res: ServerResponse,
): void {
  if (mockState.killSwitchActive) {
    writeJson(res, 409, { detail: "emergency_active" });
    return;
  }
  const { index, row } = findScheduleById(scheduleId);
  if (!row) {
    writeJson(res, 404, { detail: "schedule_not_found" });
    return;
  }
  let parsed: Partial<ScheduleRow> & { maintenance_window_cron?: string | null };
  try {
    parsed = JSON.parse(body) as typeof parsed;
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }

  if (typeof parsed.cron_expression === "string" && parsed.cron_expression === "* * * * *") {
    writeJson(res, 422, { detail: "invalid_cron_expression" });
    return;
  }
  if (typeof parsed.name === "string") {
    const wanted = parsed.name.trim();
    const conflict = mockState.schedules.find(
      (s) =>
        s.tenant_id === row.tenant_id &&
        s.name === wanted &&
        s.id !== row.id,
    );
    if (conflict) {
      writeJson(res, 409, { detail: "schedule_name_conflict" });
      return;
    }
  }

  const next: ScheduleRow = {
    ...row,
    ...(typeof parsed.name === "string" ? { name: parsed.name.trim() } : {}),
    ...(typeof parsed.cron_expression === "string"
      ? { cron_expression: parsed.cron_expression.trim() }
      : {}),
    ...(typeof parsed.target_url === "string"
      ? { target_url: parsed.target_url.trim() }
      : {}),
    ...(typeof parsed.scan_mode === "string"
      ? { scan_mode: parsed.scan_mode }
      : {}),
    ...(typeof parsed.enabled === "boolean" ? { enabled: parsed.enabled } : {}),
    ...(typeof parsed.maintenance_window_cron === "string"
      ? {
          maintenance_window_cron:
            parsed.maintenance_window_cron.trim() === ""
              ? null
              : parsed.maintenance_window_cron.trim(),
        }
      : {}),
    updated_at: nowIso(),
  };
  mockState.schedules[index] = next;
  writeJson(res, 200, buildScheduleResponse(next));
}

function handleScheduleDelete(
  scheduleId: string,
  res: ServerResponse,
): void {
  if (mockState.killSwitchActive) {
    writeJson(res, 409, { detail: "emergency_active" });
    return;
  }
  const { index } = findScheduleById(scheduleId);
  if (index < 0) {
    writeJson(res, 404, { detail: "schedule_not_found" });
    return;
  }
  mockState.schedules.splice(index, 1);
  res.writeHead(204);
  res.end();
}

function handleScheduleRunNow(
  scheduleId: string,
  url: URL,
  body: string,
  res: ServerResponse,
): void {
  const { row } = findScheduleById(scheduleId);
  if (!row) {
    writeJson(res, 404, { detail: "schedule_not_found" });
    return;
  }

  let parsed: { bypass_maintenance_window?: boolean; reason?: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return;
  }
  const reason = (parsed.reason ?? "").trim();
  const bypass = parsed.bypass_maintenance_window === true;

  if (reason.length < 10) {
    writeJson(res, 422, { detail: "validation_failed" });
    return;
  }

  // Test-control flags first so a green deterministic path always wins
  // over the synthetic seed state.
  if (url.searchParams.get("_test_emergency_active") === "true") {
    writeJson(res, 409, { detail: "emergency_active" });
    return;
  }
  if (mockState.killSwitchActive) {
    writeJson(res, 409, { detail: "emergency_active" });
    return;
  }
  if (
    url.searchParams.get("_test_in_maintenance") === "true" &&
    !bypass
  ) {
    writeJson(res, 409, { detail: "in_maintenance_window" });
    return;
  }

  // Sentinel maintenance-window: a schedule whose `maintenance_window_cron`
  // is the catch-all `"* * * * *"` is treated as ALWAYS inside its own
  // window. The mock doesn't ship a real cron parser, so we use this
  // string as a stable signal — any test that wants to exercise the
  // 409 branch can seed a schedule with this value (or PATCH its
  // existing one) and the next run-now will reject unless `bypass` is
  // set. This keeps E2E tests deterministic without dragging
  // `cron-parser` into the mock.
  const scheduleRow = (row as { maintenance_window_cron?: unknown }).maintenance_window_cron;
  if (
    typeof scheduleRow === "string" &&
    scheduleRow.trim() === "* * * * *" &&
    !bypass
  ) {
    writeJson(res, 409, { detail: "in_maintenance_window" });
    return;
  }

  const enqueuedAt = nowIso();
  const taskId = `mock-task-${nextAuditId().slice(-12)}`;
  const auditId = nextAuditId();
  writeJson(res, 202, {
    schedule_id: row.id,
    enqueued_task_id: taskId,
    bypassed_maintenance_window: bypass,
    enqueued_at: enqueuedAt,
    audit_id: auditId,
  });
}

// ──────────────────────────────────────────────────────────────────────
// T41 — webhook DLQ list / replay / abandon
// ──────────────────────────────────────────────────────────────────────

function deriveTriageStatus(
  row: DlqRow,
): "pending" | "replayed" | "abandoned" {
  if (row.replayed_at !== null) return "replayed";
  if (row.abandoned_at !== null) return "abandoned";
  return "pending";
}

function projectDlqRow(row: DlqRow): JsonValue {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    adapter_name: row.adapter_name,
    event_type: row.event_type,
    event_id: row.event_id,
    target_url_hash: row.target_url_hash,
    attempt_count: row.attempt_count,
    last_error_code: row.last_error_code,
    last_status_code: row.last_status_code,
    next_retry_at: row.next_retry_at,
    created_at: row.created_at,
    replayed_at: row.replayed_at,
    abandoned_at: row.abandoned_at,
    abandoned_reason: row.abandoned_reason,
    triage_status: deriveTriageStatus(row),
  };
}

function handleDlqList(
  url: URL,
  headers: IncomingMessage["headers"],
  res: ServerResponse,
): void {
  const role = headerValue(headers, "x-admin-role");
  if (role !== "admin" && role !== "super-admin") {
    writeJson(res, 403, { detail: "forbidden" });
    return;
  }
  const tenantHeader = headerValue(headers, "x-admin-tenant");
  if (role === "admin" && !tenantHeader) {
    writeJson(res, 403, { detail: "tenant_required" });
    return;
  }

  const statusFilter = url.searchParams.get("status");
  const adapterFilter = url.searchParams.get("adapter_name")?.trim() ?? "";
  const createdAfter = url.searchParams.get("created_after");
  const createdBefore = url.searchParams.get("created_before");
  const offset = Math.max(
    0,
    Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0,
  );
  const limit = Math.min(
    200,
    Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "50", 10) || 50),
  );

  let items = mockState.dlqEntries.slice();
  // admin → strict tenant scope; super-admin honours optional filter.
  if (role === "admin") {
    items = items.filter((row) => row.tenant_id === tenantHeader);
  } else if (tenantHeader) {
    items = items.filter((row) => row.tenant_id === tenantHeader);
  }
  if (statusFilter === "pending" || statusFilter === "replayed" || statusFilter === "abandoned") {
    items = items.filter((row) => deriveTriageStatus(row) === statusFilter);
  }
  if (adapterFilter !== "") {
    items = items.filter((row) => row.adapter_name === adapterFilter);
  }
  if (createdAfter) {
    const ts = Date.parse(createdAfter);
    if (!Number.isNaN(ts)) {
      items = items.filter((row) => Date.parse(row.created_at) >= ts);
    }
  }
  if (createdBefore) {
    const ts = Date.parse(createdBefore);
    if (!Number.isNaN(ts)) {
      items = items.filter((row) => Date.parse(row.created_at) <= ts);
    }
  }

  const total = items.length;
  const sliced = items.slice(offset, offset + limit);
  writeJson(res, 200, {
    items: sliced.map(projectDlqRow),
    total,
    limit,
    offset,
  });
}

function parseDlqMutationBody(
  body: string,
  res: ServerResponse,
): { reason: string } | null {
  let parsed: { reason?: unknown };
  try {
    parsed = JSON.parse(body) as { reason?: unknown };
  } catch {
    writeJson(res, 400, { detail: "invalid_json" });
    return null;
  }
  const reason =
    typeof parsed.reason === "string" ? parsed.reason.trim() : "";
  if (reason.length < 10 || reason.length > 500) {
    writeJson(res, 422, { detail: "validation_failed" });
    return null;
  }
  return { reason };
}

function handleDlqReplay(
  entryId: string,
  body: string,
  headers: IncomingMessage["headers"],
  res: ServerResponse,
): void {
  const role = headerValue(headers, "x-admin-role");
  if (role !== "admin" && role !== "super-admin") {
    writeJson(res, 403, { detail: "forbidden" });
    return;
  }
  const tenantHeader = headerValue(headers, "x-admin-tenant");
  if (role === "admin" && !tenantHeader) {
    writeJson(res, 403, { detail: "tenant_required" });
    return;
  }

  // Body validation runs FIRST so the deterministic-validation sentinel
  // works for any reason (the reason is what's invalid, not the id).
  // For all other sentinels the body must be valid to surface the
  // sentinel's intended status code.
  const parsedBody = parseDlqMutationBody(body, res);
  if (parsedBody === null) return;

  switch (entryId) {
    case DLQ_SENTINEL_NOT_FOUND:
      writeJson(res, 404, { detail: "dlq_entry_not_found" });
      return;
    case DLQ_SENTINEL_ALREADY_REPLAYED:
      writeJson(res, 409, { detail: "already_replayed" });
      return;
    case DLQ_SENTINEL_ALREADY_ABANDONED:
      writeJson(res, 409, { detail: "already_abandoned" });
      return;
    case DLQ_SENTINEL_VALIDATION:
      writeJson(res, 422, { detail: "validation_failed" });
      return;
    case DLQ_SENTINEL_SERVER_ERROR:
      writeJson(res, 500, { detail: "server_error" });
      return;
    case DLQ_SENTINEL_STORE_UNAVAILABLE:
      writeJson(res, 503, { detail: "store_unavailable" });
      return;
    case DLQ_SENTINEL_FORBIDDEN:
      writeJson(res, 403, { detail: "forbidden" });
      return;
    case DLQ_SENTINEL_REPLAY_FAILED: {
      const idx = mockState.dlqEntries.findIndex((row) => row.id === entryId);
      if (idx >= 0) {
        const row = mockState.dlqEntries[idx];
        mockState.dlqEntries[idx] = {
          ...row,
          attempt_count: row.attempt_count + 1,
          last_error_code: "http_500",
          last_status_code: 500,
        };
      }
      const target = mockState.dlqEntries[idx] ?? mockState.dlqEntries[0];
      writeJson(res, 202, {
        entry_id: entryId,
        success: false,
        attempt_count: target.attempt_count,
        new_status: "pending",
        audit_id: nextAuditId(),
        message_code: "replay_failed",
      });
      return;
    }
    default: {
      const idx = mockState.dlqEntries.findIndex((row) => row.id === entryId);
      if (idx < 0) {
        writeJson(res, 404, { detail: "dlq_entry_not_found" });
        return;
      }
      const row = mockState.dlqEntries[idx];
      // Tenant scope check for admin (mock parity with backend).
      if (role === "admin" && row.tenant_id !== tenantHeader) {
        writeJson(res, 404, { detail: "dlq_entry_not_found" });
        return;
      }
      if (row.replayed_at !== null) {
        writeJson(res, 409, { detail: "already_replayed" });
        return;
      }
      if (row.abandoned_at !== null) {
        writeJson(res, 409, { detail: "already_abandoned" });
        return;
      }
      const replayedAt = nowIso();
      mockState.dlqEntries[idx] = {
        ...row,
        attempt_count: row.attempt_count + 1,
        replayed_at: replayedAt,
      };
      writeJson(res, 202, {
        entry_id: entryId,
        success: true,
        attempt_count: row.attempt_count + 1,
        new_status: "replayed",
        audit_id: nextAuditId(),
        message_code: "replay_succeeded",
      });
      return;
    }
  }
}

function handleDlqAbandon(
  entryId: string,
  body: string,
  headers: IncomingMessage["headers"],
  res: ServerResponse,
): void {
  const role = headerValue(headers, "x-admin-role");
  if (role !== "admin" && role !== "super-admin") {
    writeJson(res, 403, { detail: "forbidden" });
    return;
  }
  const tenantHeader = headerValue(headers, "x-admin-tenant");
  if (role === "admin" && !tenantHeader) {
    writeJson(res, 403, { detail: "tenant_required" });
    return;
  }

  const parsedBody = parseDlqMutationBody(body, res);
  if (parsedBody === null) return;

  switch (entryId) {
    case DLQ_SENTINEL_NOT_FOUND:
      writeJson(res, 404, { detail: "dlq_entry_not_found" });
      return;
    case DLQ_SENTINEL_ALREADY_REPLAYED:
      writeJson(res, 409, { detail: "already_replayed" });
      return;
    case DLQ_SENTINEL_ALREADY_ABANDONED:
      writeJson(res, 409, { detail: "already_abandoned" });
      return;
    case DLQ_SENTINEL_VALIDATION:
      writeJson(res, 422, { detail: "validation_failed" });
      return;
    case DLQ_SENTINEL_SERVER_ERROR:
      writeJson(res, 500, { detail: "server_error" });
      return;
    case DLQ_SENTINEL_STORE_UNAVAILABLE:
      writeJson(res, 503, { detail: "store_unavailable" });
      return;
    case DLQ_SENTINEL_FORBIDDEN:
      writeJson(res, 403, { detail: "forbidden" });
      return;
    default: {
      const idx = mockState.dlqEntries.findIndex((row) => row.id === entryId);
      if (idx < 0) {
        writeJson(res, 404, { detail: "dlq_entry_not_found" });
        return;
      }
      const row = mockState.dlqEntries[idx];
      if (role === "admin" && row.tenant_id !== tenantHeader) {
        writeJson(res, 404, { detail: "dlq_entry_not_found" });
        return;
      }
      if (row.replayed_at !== null) {
        writeJson(res, 409, { detail: "already_replayed" });
        return;
      }
      if (row.abandoned_at !== null) {
        writeJson(res, 409, { detail: "already_abandoned" });
        return;
      }
      const abandonedAt = nowIso();
      mockState.dlqEntries[idx] = {
        ...row,
        abandoned_at: abandonedAt,
        abandoned_reason: "operator",
      };
      writeJson(res, 200, {
        entry_id: entryId,
        new_status: "abandoned",
        audit_id: nextAuditId(),
      });
      return;
    }
  }
}

function headerValue(
  headers: IncomingMessage["headers"],
  name: string,
): string {
  const raw = headers[name];
  if (typeof raw === "string") return raw.trim();
  if (Array.isArray(raw) && raw.length > 0) {
    const first = raw[0];
    return typeof first === "string" ? first.trim() : "";
  }
  return "";
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

  // ──────────────────────────────────────────────────────────────────
  // T36 — bulk-cancel + emergency surface
  // ──────────────────────────────────────────────────────────────────
  if (path === "/api/v1/admin/scans/bulk-cancel" && method === "POST") {
    const body = await readBody(req);
    handleBulkScanCancel(body, res);
    return;
  }
  if (path === "/api/v1/admin/system/emergency/status" && method === "GET") {
    handleEmergencyStatus(url, res);
    return;
  }
  if (path === "/api/v1/admin/system/emergency/throttle" && method === "POST") {
    const body = await readBody(req);
    handleEmergencyThrottle(body, res);
    return;
  }
  if (path === "/api/v1/admin/system/emergency/stop_all" && method === "POST") {
    const body = await readBody(req);
    handleEmergencyStopAll(body, res);
    return;
  }
  if (path === "/api/v1/admin/system/emergency/resume_all" && method === "POST") {
    const body = await readBody(req);
    handleEmergencyResumeAll(body, res);
    return;
  }
  if (path === "/api/v1/admin/system/emergency/audit-trail" && method === "GET") {
    handleEmergencyAuditTrail(url, res);
    return;
  }

  // ──────────────────────────────────────────────────────────────────
  // T36 — scan schedules CRUD + run-now
  // ──────────────────────────────────────────────────────────────────
  if (path === "/api/v1/admin/scan-schedules" && method === "GET") {
    handleSchedulesList(url, res);
    return;
  }
  if (path === "/api/v1/admin/scan-schedules" && method === "POST") {
    const body = await readBody(req);
    handleScheduleCreate(url, body, res);
    return;
  }
  const scheduleRunNowMatch = path.match(
    /^\/api\/v1\/admin\/scan-schedules\/([^/]+)\/run-now$/,
  );
  if (scheduleRunNowMatch && method === "POST") {
    const body = await readBody(req);
    handleScheduleRunNow(scheduleRunNowMatch[1], url, body, res);
    return;
  }
  const scheduleByIdMatch = path.match(
    /^\/api\/v1\/admin\/scan-schedules\/([^/]+)$/,
  );
  if (scheduleByIdMatch && method === "PATCH") {
    const body = await readBody(req);
    handleScheduleUpdate(scheduleByIdMatch[1], body, res);
    return;
  }
  if (scheduleByIdMatch && method === "DELETE") {
    handleScheduleDelete(scheduleByIdMatch[1], res);
    return;
  }

  // ──────────────────────────────────────────────────────────────────
  // T41 — webhook DLQ list / replay / abandon
  // ──────────────────────────────────────────────────────────────────
  if (path === "/api/v1/admin/webhooks/dlq" && method === "GET") {
    handleDlqList(url, req.headers, res);
    return;
  }
  const dlqReplayMatch = path.match(
    /^\/api\/v1\/admin\/webhooks\/dlq\/([^/]+)\/replay$/,
  );
  if (dlqReplayMatch && method === "POST") {
    const body = await readBody(req);
    handleDlqReplay(dlqReplayMatch[1], body, req.headers, res);
    return;
  }
  const dlqAbandonMatch = path.match(
    /^\/api\/v1\/admin\/webhooks\/dlq\/([^/]+)\/abandon$/,
  );
  if (dlqAbandonMatch && method === "POST") {
    const body = await readBody(req);
    handleDlqAbandon(dlqAbandonMatch[1], body, req.headers, res);
    return;
  }

  // Mock-only state-reset endpoint. Lives outside `/admin/*` so the real
  // backend never has a route there even if a stale BACKEND_URL config
  // accidentally pointed at production. The mock requires no body.
  if (path === "/api/v1/__test__/reset" && method === "POST") {
    resetMockState();
    res.writeHead(204);
    res.end();
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

/**
 * Stable, public-by-design ids for the seeded scan-schedules. Test
 * specs import these so a future seed change ripples through one place
 * only. Names are also stable to keep typed-name confirmation gates
 * deterministic.
 */
export const MOCK_SCHEDULES = {
  primaryNightly: {
    id: "55555555-aaaa-bbbb-cccc-111111111111",
    name: "Nightly api scan",
    tenantId: MOCK_TENANT_ID,
  },
  primaryHourlyMaint: {
    id: "55555555-aaaa-bbbb-cccc-222222222222",
    name: "Hourly internal probe",
    tenantId: MOCK_TENANT_ID,
  },
  secondaryDaily: {
    id: "55555555-aaaa-bbbb-cccc-333333333333",
    name: "Beta tenant cron",
    tenantId: MOCK_SECONDARY_TENANT_ID,
  },
} as const;

/**
 * Stable DLQ sentinel ids exported for the T41 Vitest + Playwright
 * suites. Each id deterministically triggers ONE member of
 * `WEBHOOK_DLQ_FAILURE_TAXONOMY` on both the replay and abandon routes;
 * the list endpoint returns all eight rows interleaved with the seed.
 *
 * NB: `notFound` lives in the seed too — listing it back exercises the
 * "cross-tenant existence-leak" path when the caller's `X-Admin-Tenant`
 * doesn't match. The mock follows the backend's contract: a missing
 * row and a cross-tenant probe both return 404 `dlq_entry_not_found`.
 */
export const MOCK_DLQ_SENTINELS = {
  notFound: DLQ_SENTINEL_NOT_FOUND,
  alreadyReplayed: DLQ_SENTINEL_ALREADY_REPLAYED,
  alreadyAbandoned: DLQ_SENTINEL_ALREADY_ABANDONED,
  replayFailed: DLQ_SENTINEL_REPLAY_FAILED,
  validationFailed: DLQ_SENTINEL_VALIDATION,
  serverError: DLQ_SENTINEL_SERVER_ERROR,
  storeUnavailable: DLQ_SENTINEL_STORE_UNAVAILABLE,
  forbidden: DLQ_SENTINEL_FORBIDDEN,
} as const;
