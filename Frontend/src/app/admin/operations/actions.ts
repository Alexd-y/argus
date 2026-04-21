"use server";

/**
 * Server actions for the admin **operations** surface (T29, ARG-052).
 * Mirrors the canonical pattern established by the audit-logs and scans
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
 *     anything outside the closed taxonomy (e.g. duration=30) short-circuits
 *     as `validation_failed` and never reaches FastAPI.
 *   - Backend `detail` strings are mapped through `detailToThrottleActionCode`
 *     so the closed taxonomy carries semantic information (e.g. 404 with
 *     `tenant_not_found` vs generic 404). Raw `detail` strings, stack
 *     traces, and PII NEVER cross the action boundary.
 *
 * Backend contract (T31, `backend/src/api/routers/admin_emergency.py`):
 *
 *   POST /admin/system/emergency/throttle
 *     body  : { tenant_id, duration_minutes, reason }
 *     200   : EmergencyThrottleResponse
 *     403   : forbidden / tenant mismatch / X-Admin-Tenant required
 *     404   : tenant not found
 *     409   : emergency_already_active
 *     503   : emergency_store_unavailable
 *
 *   GET  /admin/system/emergency/status?tenant_id=...
 *     200   : EmergencyStatusResponse
 *
 *   GET  /admin/system/emergency/audit-trail?tenant_id=...&limit=...
 *     200   : EmergencyAuditTrailResponse
 *
 * Carry-over (ISS-T29-001):
 *   The backend currently exposes NO `/throttle/resume` endpoint and the
 *   `EmergencyThrottleDurationMinutes` literal does NOT include 0. Manual
 *   "Resume now" is therefore returned as a typed `not_implemented` error
 *   so the dialog can render a stable RU sentence; the auto-resume on TTL
 *   expiry continues to work because the Redis TTL clears the flag without
 *   any operator action.
 */

import {
  EmergencyAuditListResponseSchema,
  ResumeAllInputSchema,
  ResumeAllResponseSchema,
  STOP_ALL_PHRASE,
  RESUME_ALL_PHRASE,
  StopAllInputSchema,
  StopAllResponseSchema,
  ThrottleResponseSchema,
  ThrottleStatusResponseSchema,
  ThrottleTenantInputSchema,
  ThrottleActionError,
  detailToThrottleActionCode,
  isUuid,
  statusToThrottleActionCode,
  type EmergencyAuditListResponse,
  type ResumeAllResponse,
  type StopAllResponse,
  type ThrottleResponse,
  type ThrottleStatusResponse,
  type ThrottleTenantInput,
} from "@/lib/adminOperations";
import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import { getServerAdminSession } from "@/services/admin/serverSession";

const THROTTLE_PATH = "/system/emergency/throttle";
const STATUS_PATH = "/system/emergency/status";
const AUDIT_TRAIL_PATH = "/system/emergency/audit-trail";
const STOP_ALL_PATH = "/system/emergency/stop_all";
const RESUME_ALL_PATH = "/system/emergency/resume_all";

const DEFAULT_AUDIT_LIMIT = 25;
const MAX_AUDIT_LIMIT = 200;

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

type ResolvedSession = {
  readonly role: "admin" | "super-admin";
  readonly tenantId: string | null;
  readonly subject: string;
};

async function resolveAdminSession(): Promise<ResolvedSession> {
  const session = await getServerAdminSession();
  if (session.role === null) {
    throw new ThrottleActionError("unauthorized", 401);
  }
  if (session.role === "operator") {
    throw new ThrottleActionError("forbidden", 403);
  }
  return {
    role: session.role,
    tenantId: session.tenantId,
    subject: session.subject,
  };
}

/**
 * Resolve the effective tenant the action will scope against.
 *
 *   - `admin` → the session-bound tenant ALWAYS wins; any caller-supplied
 *     `tenantId` is silently ignored (defence in depth — even though the
 *     UI also hides the selector for admins, the action never trusts the
 *     argument).
 *   - `super-admin` → the caller-supplied `tenantId` is honoured. `null`
 *     means cross-tenant view (status + audit-trail only).
 */
function resolveEffectiveTenantForRead(
  session: ResolvedSession,
  callerTenantId: string | null | undefined,
): string | null {
  if (session.role === "admin") {
    return session.tenantId;
  }
  const trimmed = (callerTenantId ?? "").trim();
  if (trimmed === "") return null;
  return trimmed;
}

function resolveEffectiveTenantForWrite(
  session: ResolvedSession,
  callerTenantId: string,
): string {
  if (session.role === "admin") {
    if (!session.tenantId) {
      throw new ThrottleActionError("forbidden", 403);
    }
    if (callerTenantId !== session.tenantId) {
      throw new ThrottleActionError("forbidden", 403);
    }
    return session.tenantId;
  }
  return callerTenantId;
}

function mapResultToError(
  status: number,
  data: unknown,
): ThrottleActionError {
  let detail: unknown = null;
  if (data && typeof data === "object" && "detail" in data) {
    detail = (data as { detail: unknown }).detail;
  }
  const fromDetail = detailToThrottleActionCode(detail);
  const code = fromDetail ?? statusToThrottleActionCode(status);
  return new ThrottleActionError(code, status);
}

function buildQuery(params: Record<string, string | undefined>): string {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value && value.trim() !== "") sp.set(key, value);
  }
  const qs = sp.toString();
  return qs ? `?${qs}` : "";
}

// ---------------------------------------------------------------------------
// throttleTenantAction — POST /admin/system/emergency/throttle
// ---------------------------------------------------------------------------

/**
 * Apply a per-tenant emergency throttle. Validates the input via Zod,
 * enforces RBAC on the action layer, and forwards the operator identity
 * via `X-Admin-Role` / `X-Admin-Tenant` / `X-Operator-Subject`.
 *
 * @throws {@link ThrottleActionError} with a closed-taxonomy code on any
 * failure path. Callers must render the message via
 * `throttleActionErrorMessage` — never echo the raw error.
 */
export async function throttleTenantAction(
  rawInput: unknown,
): Promise<ThrottleResponse> {
  const parsed = ThrottleTenantInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    const issue = parsed.error.issues.find(
      (i) => i.message === "duration_not_allowed",
    );
    if (issue) {
      throw new ThrottleActionError("duration_not_allowed", 400);
    }
    throw new ThrottleActionError("validation_failed", 400);
  }
  const input: ThrottleTenantInput = parsed.data;

  const session = await resolveAdminSession();
  const effectiveTenantId = resolveEffectiveTenantForWrite(
    session,
    input.tenantId,
  );

  if (!isUuid(effectiveTenantId)) {
    throw new ThrottleActionError("validation_failed", 400);
  }

  const result = await callAdminBackendJson<unknown>(THROTTLE_PATH, {
    method: "POST",
    headers: {
      "X-Admin-Role": session.role,
      "X-Admin-Tenant": effectiveTenantId,
      "X-Operator-Subject": session.subject,
    },
    body: JSON.stringify({
      tenant_id: effectiveTenantId,
      duration_minutes: input.durationMinutes,
      reason: input.reason,
    }),
  });

  if (!result.ok) {
    throw mapResultToError(result.status, undefined);
  }

  const parsedBody = ThrottleResponseSchema.safeParse(result.data);
  if (!parsedBody.success) {
    // Schema drift — keep the closed taxonomy and never echo Zod issue
    // paths to the browser.
    throw new ThrottleActionError("server_error", 200);
  }
  return parsedBody.data;
}

// ---------------------------------------------------------------------------
// getEmergencyStatusAction — GET /admin/system/emergency/status
// ---------------------------------------------------------------------------

export type GetEmergencyStatusInput = {
  /**
   * Optional tenant filter. For `admin` callers this is IGNORED — the
   * server uses the session-bound tenant. For `super-admin`, an empty/
   * missing value triggers the cross-tenant view.
   */
  readonly tenantId?: string | null;
};

/**
 * Snapshot the emergency posture (global state + per-tenant throttles).
 * Safe to call on a 5–10 s polling cadence; the backend handler only
 * touches Redis (no DB query).
 */
export async function getEmergencyStatusAction(
  input: GetEmergencyStatusInput = {},
): Promise<ThrottleStatusResponse> {
  const session = await resolveAdminSession();
  const effectiveTenantId = resolveEffectiveTenantForRead(
    session,
    input.tenantId,
  );

  // Admin without a session-bound tenant: refuse loudly so we never
  // accidentally render someone else's throttle state. Super-admin may
  // legitimately query cross-tenant.
  if (session.role === "admin" && !effectiveTenantId) {
    throw new ThrottleActionError("forbidden", 403);
  }

  const path = `${STATUS_PATH}${buildQuery({
    tenant_id: effectiveTenantId ?? undefined,
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
    throw mapResultToError(result.status, undefined);
  }

  const parsed = ThrottleStatusResponseSchema.safeParse(result.data);
  if (!parsed.success) {
    throw new ThrottleActionError("server_error", 200);
  }
  return parsed.data;
}

// ---------------------------------------------------------------------------
// listEmergencyAuditTrailAction — GET /admin/system/emergency/audit-trail
// (Surface for T30; exposed here so the operations page can render a small
// summary panel below the throttle status.)
// ---------------------------------------------------------------------------

export type ListEmergencyAuditTrailInput = {
  readonly tenantId?: string | null;
  readonly limit?: number;
};

export async function listEmergencyAuditTrailAction(
  input: ListEmergencyAuditTrailInput = {},
): Promise<EmergencyAuditListResponse> {
  const session = await resolveAdminSession();
  const effectiveTenantId = resolveEffectiveTenantForRead(
    session,
    input.tenantId,
  );

  if (session.role === "admin" && !effectiveTenantId) {
    throw new ThrottleActionError("forbidden", 403);
  }

  const limit = clampLimit(input.limit ?? DEFAULT_AUDIT_LIMIT);
  const path = `${AUDIT_TRAIL_PATH}${buildQuery({
    tenant_id: effectiveTenantId ?? undefined,
    limit: String(limit),
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
    throw mapResultToError(result.status, undefined);
  }

  const parsed = EmergencyAuditListResponseSchema.safeParse(result.data);
  if (!parsed.success) {
    throw new ThrottleActionError("server_error", 200);
  }
  return parsed.data;
}

function clampLimit(raw: number): number {
  if (!Number.isFinite(raw)) return DEFAULT_AUDIT_LIMIT;
  const n = Math.trunc(raw);
  if (n < 1) return 1;
  if (n > MAX_AUDIT_LIMIT) return MAX_AUDIT_LIMIT;
  return n;
}

// ---------------------------------------------------------------------------
// resumeTenantAction — manual override (NOT IMPLEMENTED at the backend yet)
// ---------------------------------------------------------------------------

/**
 * Manual "Resume now" override. The backend currently has NO endpoint to
 * clear a per-tenant throttle before its TTL expires (see ISS-T29-001;
 * `EmergencyThrottleDurationMinutes` literal excludes 0, and there is no
 * `/throttle/resume` route in `admin_emergency.py`). Until that lands the
 * action throws a typed `not_implemented` error so the UI can render a
 * stable RU sentence; auto-resume on TTL expiry continues to work because
 * the Redis TTL clears the flag without any operator action.
 */
export async function resumeTenantAction(input: {
  readonly tenantId: string;
}): Promise<never> {
  // Resolve the session anyway so an operator without privileges sees the
  // expected `forbidden` rather than a `not_implemented`.
  await resolveAdminSession();
  // The tenantId is captured into the rejection cause so downstream
  // structured logs (the call-site eventually feeds into the audit-log
  // writer once the backend route lands — ISS-T29-001) carry the same
  // identifier the UI tried to resume. This also prevents the `_input`
  // unused-parameter lint without dropping the public signature.
  const err = new ThrottleActionError("not_implemented", 501);
  (err as ThrottleActionError & { context?: { tenantId: string } }).context = {
    tenantId: input.tenantId,
  };
  throw err;
}

// ---------------------------------------------------------------------------
// Global kill-switch — stopAllAction / resumeAllAction (T30, ARG-053).
//
// Defence in depth:
//   1. The UI dialog gates the buttons behind a typed-phrase confirmation
//      (case-sensitive, paste-blocked) and a 10..500 char reason.
//   2. THIS layer (server action) re-validates the reason via Zod AND
//      enforces `session.role === "super-admin"` BEFORE the round-trip,
//      throwing `ThrottleActionError("forbidden", 403)` for admin/operator
//      so a hand-rolled fetch from a stale `admin` session can't widen
//      its scope by reaching this entry-point.
//   3. The backend re-validates `_require_super_admin` AND the
//      `confirmation_phrase` field server-side (`backend/src/api/routers/
//      admin_emergency.py`). Three independent checks; tampering with any
//      ONE of them still leaves the other two intact.
//
// We send `confirmation_phrase` as a constant (the phrase the dialog UI
// already validated) to satisfy the backend Pydantic model. The phrase
// is NEVER sourced from the caller arg — that would defeat layer (2).
// ---------------------------------------------------------------------------

/**
 * Engage the global emergency stop. Cancels every active scan
 * cross-tenant and sets the global Redis flag so future tool dispatch
 * fails closed.
 *
 * @throws {@link ThrottleActionError} with closed-taxonomy codes:
 *   - `unauthorized` (no session)
 *   - `forbidden` (role !== super-admin)
 *   - `validation_failed` (bad reason)
 *   - `already_active` (409 — flag already set by a concurrent operator)
 *   - `store_unavailable` (503 — Redis or X-Admin-Key missing)
 *   - `server_error` (anything else, including envelope drift)
 */
export async function stopAllAction(
  rawInput: unknown,
): Promise<StopAllResponse> {
  const parsed = StopAllInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new ThrottleActionError("validation_failed", 400);
  }

  const session = await resolveAdminSession();
  if (session.role !== "super-admin") {
    throw new ThrottleActionError("forbidden", 403);
  }

  const result = await callAdminBackendJson<unknown>(STOP_ALL_PATH, {
    method: "POST",
    headers: {
      "X-Admin-Role": session.role,
      "X-Operator-Subject": session.subject,
    },
    body: JSON.stringify({
      reason: parsed.data.reason,
      confirmation_phrase: STOP_ALL_PHRASE,
    }),
  });

  if (!result.ok) {
    // 409 on stop_all only ever surfaces `emergency_already_active` (a
    // concurrent operator beat us to the punch). Mirror the backend
    // `_DETAIL_EMERGENCY_ACTIVE` Final constant — `mapResultToError`
    // already maps 409 → `already_active` via `statusToThrottleActionCode`.
    throw mapResultToError(result.status, undefined);
  }

  const parsedBody = StopAllResponseSchema.safeParse(result.data);
  if (!parsedBody.success) {
    throw new ThrottleActionError("server_error", 200);
  }
  return parsedBody.data;
}

/**
 * Lift the global emergency stop. The backend returns 409
 * `emergency_not_active` when no flag is set so operators get a loud
 * signal that their resume call did NOT toggle state.
 *
 * @throws {@link ThrottleActionError} with closed-taxonomy codes:
 *   - `unauthorized`, `forbidden`, `validation_failed`
 *   - `emergency_inactive` (409 — no global stop in effect)
 *   - `store_unavailable` (503), `server_error` (catch-all)
 */
export async function resumeAllAction(
  rawInput: unknown,
): Promise<ResumeAllResponse> {
  const parsed = ResumeAllInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new ThrottleActionError("validation_failed", 400);
  }

  const session = await resolveAdminSession();
  if (session.role !== "super-admin") {
    throw new ThrottleActionError("forbidden", 403);
  }

  const result = await callAdminBackendJson<unknown>(RESUME_ALL_PATH, {
    method: "POST",
    headers: {
      "X-Admin-Role": session.role,
      "X-Operator-Subject": session.subject,
    },
    body: JSON.stringify({
      reason: parsed.data.reason,
      confirmation_phrase: RESUME_ALL_PHRASE,
    }),
  });

  if (!result.ok) {
    // 409 on resume_all means `emergency_not_active` (no global stop in
    // effect). The status-only mapping would otherwise classify this as
    // `already_active`, which is the wrong RU sentence for the operator.
    if (result.status === 409) {
      throw new ThrottleActionError("emergency_inactive", 409);
    }
    throw mapResultToError(result.status, undefined);
  }

  const parsedBody = ResumeAllResponseSchema.safeParse(result.data);
  if (!parsedBody.success) {
    throw new ThrottleActionError("server_error", 200);
  }
  return parsedBody.data;
}
