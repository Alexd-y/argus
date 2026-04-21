"use server";

/**
 * Server actions for the admin **scan-schedules** surface (T35, ARG-056).
 *
 * Mirrors the canonical pattern established by the operations and audit-logs
 * actions:
 *
 *   - `X-Admin-Key` is attached SERVER-SIDE only (`callAdminBackendJson`)
 *     and never reaches the browser.
 *   - `X-Admin-Role` / `X-Admin-Tenant` / `X-Operator-Subject` are derived
 *     EXCLUSIVELY from `getServerAdminSession()` (cookie + dev env). The
 *     browser cannot widen its own privileges by passing different values
 *     in the action arguments — `admin` callers are pinned to their
 *     session-bound tenant; `super-admin` honours the UI choice.
 *   - All write paths validate the input with Zod BEFORE the round-trip;
 *     anything outside the closed taxonomy short-circuits as
 *     `validation_failed` and never reaches FastAPI.
 *   - Backend `detail` snake_case tokens (T33 contract) are mapped through
 *     `detailToScheduleActionCode` so the closed taxonomy carries semantic
 *     information (e.g. 409 with `in_maintenance_window` vs the default
 *     `schedule_name_conflict`). Raw `detail` strings, stack traces and
 *     PII NEVER cross the action boundary.
 *
 * Backend contract (T33, `backend/src/api/routers/admin_schedules.py`):
 *
 *   GET    /admin/scan-schedules?tenant_id=&enabled=&limit=&offset=
 *     200   : ScanSchedulesListResponse
 *     403   : forbidden / tenant_id_required / tenant_header_required /
 *             tenant_mismatch
 *
 *   POST   /admin/scan-schedules
 *     201   : ScanScheduleResponse
 *     409   : schedule_name_conflict
 *     422   : invalid_cron_expression / invalid_maintenance_window_cron
 *     403   : tenant_mismatch (admin probing another tenant)
 *
 *   PATCH  /admin/scan-schedules/{id}
 *     200   : ScanScheduleResponse
 *     404   : schedule_not_found (incl. cross-tenant admin probes — T33 S1.3)
 *     409   : schedule_name_conflict
 *     422   : invalid_cron_expression / invalid_maintenance_window_cron
 *
 *   DELETE /admin/scan-schedules/{id}
 *     204   : (no body)
 *     404   : schedule_not_found (incl. cross-tenant admin probes)
 *
 *   POST   /admin/scan-schedules/{id}/run-now
 *     202   : ScanScheduleRunNowResponse
 *     404   : schedule_not_found (incl. cross-tenant admin probes)
 *     409   : in_maintenance_window OR emergency_active
 *     503   : kill-switch store unavailable (run-now treats as fail-open)
 */

import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import { getServerAdminSession } from "@/services/admin/serverSession";
import {
  RunNowInputSchema,
  RunNowResponseSchema,
  ScheduleActionError,
  ScheduleCreateInputSchema,
  ScheduleSchema,
  ScheduleUpdateInputSchema,
  SchedulesListResponseSchema,
  detailToScheduleActionCode,
  isUuid,
  statusToScheduleActionCode,
  type RunNowInput,
  type RunNowResponse,
  type Schedule,
  type ScheduleCreateInput,
  type ScheduleUpdateInput,
  type SchedulesListResponse,
} from "@/lib/adminSchedules";

const SCHEDULES_PATH = "/scan-schedules";
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

type ResolvedSession = {
  readonly role: "admin" | "super-admin";
  readonly tenantId: string | null;
  readonly subject: string;
};

type ResolvedReadSession = {
  readonly role: "operator" | "admin" | "super-admin";
  readonly tenantId: string | null;
  readonly subject: string;
};

async function resolveWriteSession(): Promise<ResolvedSession> {
  const session = await getServerAdminSession();
  if (session.role === null) {
    throw new ScheduleActionError("unauthorized", 401);
  }
  if (session.role === "operator") {
    throw new ScheduleActionError("forbidden", 403);
  }
  return {
    role: session.role,
    tenantId: session.tenantId,
    subject: session.subject,
  };
}

async function resolveReadSession(): Promise<ResolvedReadSession> {
  const session = await getServerAdminSession();
  if (session.role === null) {
    throw new ScheduleActionError("unauthorized", 401);
  }
  return {
    role: session.role,
    tenantId: session.tenantId,
    subject: session.subject,
  };
}

function resolveTenantForWrite(
  session: ResolvedSession,
  callerTenantId: string,
): string {
  if (session.role === "admin") {
    if (!session.tenantId) {
      throw new ScheduleActionError("forbidden", 403);
    }
    if (callerTenantId !== session.tenantId) {
      throw new ScheduleActionError("forbidden", 403);
    }
    return session.tenantId;
  }
  return callerTenantId;
}

/**
 * Decide which tenant filter to send to GET /scan-schedules.
 *
 *   - operator + admin → MUST be scoped to their own session tenant.
 *     Caller args are ignored (defence in depth — server also enforces).
 *   - super-admin → honours the caller arg; `null`/empty triggers the
 *     cross-tenant view (no `tenant_id` query param).
 */
function resolveTenantForRead(
  session: ResolvedReadSession,
  callerTenantId: string | null | undefined,
): string | null {
  if (session.role === "operator" || session.role === "admin") {
    if (!session.tenantId) {
      throw new ScheduleActionError("forbidden", 403);
    }
    return session.tenantId;
  }
  const trimmed = (callerTenantId ?? "").trim();
  if (trimmed === "") return null;
  return trimmed;
}

/**
 * Map a failed `callAdminBackendJson` result onto a closed-taxonomy
 * `ScheduleActionError`. We pass the RAW backend `detail` token through
 * `detailToScheduleActionCode` first so 409 can disambiguate
 * `in_maintenance_window` / `emergency_active` / `schedule_name_conflict`
 * (status-only mapping defaults to the conflict).
 */
function mapResultToError(result: {
  status: number;
  detail?: unknown;
}): ScheduleActionError {
  const fromDetail = detailToScheduleActionCode(result.detail);
  const code = fromDetail ?? statusToScheduleActionCode(result.status);
  return new ScheduleActionError(code, result.status);
}

function buildQuery(params: Record<string, string | undefined>): string {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") sp.set(key, value);
  }
  const qs = sp.toString();
  return qs ? `?${qs}` : "";
}

function clampLimit(raw: number | undefined): number {
  if (raw === undefined || !Number.isFinite(raw)) return DEFAULT_LIST_LIMIT;
  const n = Math.trunc(raw);
  if (n < 1) return 1;
  if (n > MAX_LIST_LIMIT) return MAX_LIST_LIMIT;
  return n;
}

// ---------------------------------------------------------------------------
// listSchedulesAction — GET /admin/scan-schedules
// ---------------------------------------------------------------------------

export type ListSchedulesInput = {
  readonly tenantId?: string | null;
  readonly enabled?: boolean | null;
  readonly limit?: number;
  readonly offset?: number;
};

/**
 * Paginated list of scan schedules. operator+ can read.
 *
 * @throws {@link ScheduleActionError} on RBAC, transport, or schema drift.
 */
export async function listSchedulesAction(
  input: ListSchedulesInput = {},
): Promise<SchedulesListResponse> {
  const session = await resolveReadSession();
  const effectiveTenantId = resolveTenantForRead(session, input.tenantId);

  const limit = clampLimit(input.limit);
  const offset = Math.max(0, Math.trunc(input.offset ?? 0));
  const path = `${SCHEDULES_PATH}${buildQuery({
    tenant_id: effectiveTenantId ?? undefined,
    enabled:
      input.enabled === undefined || input.enabled === null
        ? undefined
        : input.enabled
          ? "true"
          : "false",
    limit: String(limit),
    offset: String(offset),
  })}`;

  const result = await callAdminBackendJson<unknown>(path, {
    method: "GET",
    headers: {
      "X-Admin-Role": session.role,
      ...(effectiveTenantId ? { "X-Admin-Tenant": effectiveTenantId } : {}),
      "X-Operator-Subject": session.subject,
    },
  });

  if (!result.ok) {
    throw mapResultToError(result);
  }

  const parsed = SchedulesListResponseSchema.safeParse(result.data);
  if (!parsed.success) {
    throw new ScheduleActionError("server_error", 200);
  }
  return parsed.data;
}

// ---------------------------------------------------------------------------
// createScheduleAction — POST /admin/scan-schedules
// ---------------------------------------------------------------------------

/**
 * Create a new scan schedule. admin+ only; admin pinned to session tenant.
 *
 * @throws {@link ScheduleActionError} with closed-taxonomy codes:
 *   - `unauthorized`, `forbidden`
 *   - `validation_failed` (Zod failure on input)
 *   - `invalid_cron_expression` / `invalid_maintenance_window_cron`
 *   - `schedule_name_conflict`
 *   - `tenant_mismatch` (admin probing another tenant)
 *   - `store_unavailable`, `server_error`
 */
export async function createScheduleAction(
  rawInput: unknown,
): Promise<Schedule> {
  // T30 (S3-1): RBAC fail-fast BEFORE Zod so an authenticated-but-
  // unauthorised caller cannot probe the input schema.
  const session = await resolveWriteSession();

  const parsed = ScheduleCreateInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new ScheduleActionError("validation_failed", 400);
  }
  const input: ScheduleCreateInput = parsed.data;

  if (!isUuid(input.tenantId)) {
    throw new ScheduleActionError("validation_failed", 400);
  }

  const effectiveTenantId = resolveTenantForWrite(session, input.tenantId);

  const result = await callAdminBackendJson<unknown>(SCHEDULES_PATH, {
    method: "POST",
    headers: {
      "X-Admin-Role": session.role,
      "X-Admin-Tenant": effectiveTenantId,
      "X-Operator-Subject": session.subject,
    },
    body: JSON.stringify({
      tenant_id: effectiveTenantId,
      name: input.name,
      cron_expression: input.cronExpression,
      target_url: input.targetUrl,
      scan_mode: input.scanMode,
      enabled: input.enabled,
      maintenance_window_cron: input.maintenanceWindowCron,
    }),
  });

  if (!result.ok) {
    throw mapResultToError(result);
  }

  const parsedBody = ScheduleSchema.safeParse(result.data);
  if (!parsedBody.success) {
    throw new ScheduleActionError("server_error", 200);
  }
  return parsedBody.data;
}

// ---------------------------------------------------------------------------
// updateScheduleAction — PATCH /admin/scan-schedules/{id}
// ---------------------------------------------------------------------------

/**
 * Partial update of a scan schedule. admin+ only.
 *
 * S1.3 cross-tenant probes return `schedule_not_found` (NOT 403) so a
 * tenant-A admin cannot enumerate tenant-B schedule UUIDs.
 *
 * Caveat (T33 deferred): sending `maintenanceWindowCron: undefined` is the
 * only way to no-op that field. Sending an empty string clears it on the
 * client schema (Zod `.optional()`) but the backend treats `null` as
 * no-change. Therefore the UI MUST avoid sending the field unless the
 * operator actually changed it.
 */
export async function updateScheduleAction(
  scheduleId: string,
  rawInput: unknown,
): Promise<Schedule> {
  const session = await resolveWriteSession();

  if (!isUuid(scheduleId)) {
    throw new ScheduleActionError("validation_failed", 400);
  }

  const parsed = ScheduleUpdateInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new ScheduleActionError("validation_failed", 400);
  }
  const input: ScheduleUpdateInput = parsed.data;

  // Build the payload with snake_case keys, omitting undefined fields so
  // the backend's PATCH semantics ("None = no change") are honoured.
  const payload: Record<string, unknown> = {};
  if (input.name !== undefined) payload.name = input.name;
  if (input.cronExpression !== undefined)
    payload.cron_expression = input.cronExpression;
  if (input.targetUrl !== undefined) payload.target_url = input.targetUrl;
  if (input.scanMode !== undefined) payload.scan_mode = input.scanMode;
  if (input.enabled !== undefined) payload.enabled = input.enabled;
  if (input.maintenanceWindowCron !== undefined)
    payload.maintenance_window_cron = input.maintenanceWindowCron;

  const result = await callAdminBackendJson<unknown>(
    `${SCHEDULES_PATH}/${encodeURIComponent(scheduleId)}`,
    {
      method: "PATCH",
      headers: {
        "X-Admin-Role": session.role,
        ...(session.tenantId
          ? { "X-Admin-Tenant": session.tenantId }
          : {}),
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify(payload),
    },
  );

  if (!result.ok) {
    throw mapResultToError(result);
  }

  const parsedBody = ScheduleSchema.safeParse(result.data);
  if (!parsedBody.success) {
    throw new ScheduleActionError("server_error", 200);
  }
  return parsedBody.data;
}

// ---------------------------------------------------------------------------
// deleteScheduleAction — DELETE /admin/scan-schedules/{id}
// ---------------------------------------------------------------------------

/**
 * Remove a scan schedule. admin+ only. Returns void on 204.
 *
 * @throws {@link ScheduleActionError} on any failure path; cross-tenant
 * admin probes return `schedule_not_found` (T33 S1.3).
 */
export async function deleteScheduleAction(
  scheduleId: string,
): Promise<void> {
  const session = await resolveWriteSession();

  if (!isUuid(scheduleId)) {
    throw new ScheduleActionError("validation_failed", 400);
  }

  const result = await callAdminBackendJson<unknown>(
    `${SCHEDULES_PATH}/${encodeURIComponent(scheduleId)}`,
    {
      method: "DELETE",
      headers: {
        "X-Admin-Role": session.role,
        ...(session.tenantId
          ? { "X-Admin-Tenant": session.tenantId }
          : {}),
        "X-Operator-Subject": session.subject,
      },
    },
  );

  if (!result.ok) {
    throw mapResultToError(result);
  }
}

// ---------------------------------------------------------------------------
// runNowAction — POST /admin/scan-schedules/{id}/run-now
// ---------------------------------------------------------------------------

/**
 * Manually fire a schedule. admin+ only. Always re-validates kill-switch
 * AND maintenance window server-side; the UI guards exist for fast UX
 * feedback only.
 *
 * @throws {@link ScheduleActionError}:
 *   - `in_maintenance_window` (409) — operator can opt to re-issue with
 *     `bypassMaintenanceWindow: true`.
 *   - `emergency_active` (409) — operator must lift the global stop /
 *     per-tenant throttle first; this endpoint cannot bypass it.
 */
export async function runNowAction(
  scheduleId: string,
  rawInput: unknown,
): Promise<RunNowResponse> {
  const session = await resolveWriteSession();

  if (!isUuid(scheduleId)) {
    throw new ScheduleActionError("validation_failed", 400);
  }

  const parsed = RunNowInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new ScheduleActionError("validation_failed", 400);
  }
  const input: RunNowInput = parsed.data;

  const result = await callAdminBackendJson<unknown>(
    `${SCHEDULES_PATH}/${encodeURIComponent(scheduleId)}/run-now`,
    {
      method: "POST",
      headers: {
        "X-Admin-Role": session.role,
        ...(session.tenantId
          ? { "X-Admin-Tenant": session.tenantId }
          : {}),
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify({
        bypass_maintenance_window: input.bypassMaintenanceWindow,
        reason: input.reason,
      }),
    },
  );

  if (!result.ok) {
    throw mapResultToError(result);
  }

  const parsedBody = RunNowResponseSchema.safeParse(result.data);
  if (!parsedBody.success) {
    throw new ScheduleActionError("server_error", 200);
  }
  return parsedBody.data;
}

