"use server";

/**
 * Server actions for the admin audit-log viewer + chain integrity panel
 * (T22). Mirrors the canonical pattern established by T20:
 *
 *   - `X-Admin-Key` is attached SERVER-SIDE only (`callAdminBackendJson`),
 *     never reaches the browser. Even if a malicious client bypasses the
 *     React UI, the action layer is the only place that can talk to FastAPI.
 *   - `X-Admin-Role`, `X-Admin-Tenant`, `X-Operator-Subject` are derived
 *     from `getServerAdminSession()` (cookie + dev-env fallback). The
 *     browser cannot widen its own privileges by passing different values
 *     in the action arguments — the action ignores any caller-supplied
 *     identity hints.
 *   - For `admin` role, `params.tenantId` is IGNORED and replaced with
 *     `session.tenantId`. For `super-admin`, the URL/UI choice is honoured
 *     (empty = cross-tenant view).
 *   - Responses are validated with Zod. A schema mismatch is treated as a
 *     `server_error` (closed taxonomy) — the browser never sees Zod issue
 *     paths.
 */

import {
  AdminAuditLogsError,
  AuditChainVerifyResponseSchema,
  AuditLogsListResponseSchema,
  statusToAdminAuditLogsCode,
  type AuditChainVerifyResponse,
  type AuditLogsListResponse,
  type ListAdminAuditLogsParams,
  type VerifyAuditChainParams,
} from "@/lib/adminAuditLogs";
import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import { getServerAdminSession } from "@/services/admin/serverSession";

const LIST_PATH = "/audit-logs";
const VERIFY_PATH = "/audit-logs/verify-chain";

/**
 * Build the FastAPI query string for `GET /admin/audit-logs`. The wire names
 * (`tenant_id`, `q`, `since`, `until`, `event_type`, `limit`, `offset`)
 * match `backend/src/api/routers/admin.py::list_audit_logs`.
 *
 * `actorSubject` is mapped to `q` because the backend has no dedicated
 * actor-subject filter today — `q` is an ILIKE substring search across
 * `action`, `resource_type`, and `details`. If both `actorSubject` and a
 * separate free-text are ever supported, this is the only place that needs
 * to change.
 */
function buildListQuery(
  params: ListAdminAuditLogsParams,
  effectiveTenantId: string | null,
): URLSearchParams {
  const sp = new URLSearchParams();

  if (effectiveTenantId && effectiveTenantId.trim()) {
    sp.set("tenant_id", effectiveTenantId.trim());
  }

  if (params.eventType && params.eventType.trim()) {
    sp.set("event_type", params.eventType.trim());
  }

  if (params.actorSubject && params.actorSubject.trim()) {
    sp.set("q", params.actorSubject.trim());
  }

  if (params.since) sp.set("since", params.since);
  if (params.until) sp.set("until", params.until);

  if (params.cursor) {
    const offset = Number.parseInt(params.cursor, 10);
    if (Number.isFinite(offset) && offset >= 0) {
      sp.set("offset", String(offset));
    }
  }
  if (params.limit != null) sp.set("limit", String(params.limit));

  return sp;
}

/**
 * Build the verify-chain query string. Same wire names as the list endpoint
 * minus pagination (`limit` / `offset` / `q`).
 */
function buildVerifyQuery(
  params: VerifyAuditChainParams,
  effectiveTenantId: string | null,
): URLSearchParams {
  const sp = new URLSearchParams();

  if (effectiveTenantId && effectiveTenantId.trim()) {
    sp.set("tenant_id", effectiveTenantId.trim());
  }
  if (params.eventType && params.eventType.trim()) {
    sp.set("event_type", params.eventType.trim());
  }
  if (params.since) sp.set("since", params.since);
  if (params.until) sp.set("until", params.until);

  return sp;
}

/**
 * Resolve the tenant the action will scope its backend call to. For
 * `admin`-role operators the session-bound tenant always wins; for
 * `super-admin` the URL/UI choice is honoured (`null` = cross-tenant).
 *
 * Throws `unauthorized` when no role is resolved — the action is the only
 * place that can refuse the operation cleanly without leaking the
 * underlying 403/401 detail.
 */
async function resolveEffectiveTenant(
  paramTenantId: string | null | undefined,
): Promise<{
  role: "admin" | "super-admin";
  tenantId: string | null;
  subject: string;
}> {
  const session = await getServerAdminSession();
  if (session.role === null) {
    throw new AdminAuditLogsError("unauthorized", 401);
  }
  if (session.role === "operator") {
    throw new AdminAuditLogsError("forbidden", 403);
  }
  let effectiveTenantId: string | null;
  if (session.role === "super-admin") {
    effectiveTenantId =
      paramTenantId && paramTenantId.trim() ? paramTenantId.trim() : null;
  } else {
    effectiveTenantId = session.tenantId;
  }
  return {
    role: session.role,
    tenantId: effectiveTenantId,
    subject: session.subject,
  };
}

/**
 * Fetch a single page of admin audit logs.
 *
 * Behavioural notes:
 *   - `admin` operators without a session-bound tenant get an explicit empty
 *     page (NEVER cross-tenant data) — matches T20's S1-6 pattern.
 *   - The action synthesises a numeric-string `next_cursor` from
 *     `offset + items.length` whenever the page is full so React Query's
 *     infinite-scroll keeps working even though the underlying backend uses
 *     plain offset pagination.
 */
export async function listAdminAuditLogsAction(
  params: ListAdminAuditLogsParams = {},
): Promise<AuditLogsListResponse> {
  const { role, tenantId, subject } = await resolveEffectiveTenant(
    params.tenantId,
  );

  if (role === "admin" && tenantId === null) {
    return AuditLogsListResponseSchema.parse([]);
  }

  const qs = buildListQuery(params, tenantId).toString();
  const path = qs ? `${LIST_PATH}?${qs}` : LIST_PATH;

  const result = await callAdminBackendJson<unknown>(path, {
    method: "GET",
    headers: {
      "X-Admin-Role": role,
      ...(tenantId ? { "X-Admin-Tenant": tenantId } : {}),
      "X-Operator-Subject": subject,
    },
  });

  if (!result.ok) {
    if (result.status === 503) {
      throw new AdminAuditLogsError("network_error", 503);
    }
    throw new AdminAuditLogsError(
      statusToAdminAuditLogsCode(result.status),
      result.status,
    );
  }

  const parsed = AuditLogsListResponseSchema.safeParse(result.data);
  if (!parsed.success) {
    // Schema mismatch is a server contract drift, not a user error — keep
    // the closed taxonomy and never echo Zod issue paths to the browser.
    throw new AdminAuditLogsError("server_error", 200);
  }

  // Synthesize cursor for offset-based backend pagination so the UI's
  // infinite-scroll layer (React Query) sees a uniform contract.
  const limit = params.limit ?? 0;
  const requestedOffset = params.cursor
    ? Number.parseInt(params.cursor, 10) || 0
    : 0;
  let nextCursor: string | null = parsed.data.next_cursor;
  if (nextCursor === null && limit > 0 && parsed.data.items.length >= limit) {
    nextCursor = String(requestedOffset + parsed.data.items.length);
  }

  return {
    items: parsed.data.items,
    total: parsed.data.total,
    next_cursor: nextCursor,
  };
}

/**
 * Trigger a chain-integrity verification (T25 endpoint). Empty body — every
 * parameter travels as a typed query string.
 *
 * RBAC parity with the list action:
 *   - `operator` → `forbidden` (matches T25's stricter RBAC).
 *   - `admin` → tenant always pinned to session.
 *   - `super-admin` → optional cross-tenant scope from the UI.
 */
export async function verifyAuditChainAction(
  params: VerifyAuditChainParams = {},
): Promise<AuditChainVerifyResponse> {
  const { role, tenantId, subject } = await resolveEffectiveTenant(
    params.tenantId,
  );

  if (role === "admin" && tenantId === null) {
    // Admin without bound tenant: refuse rather than silently verifying
    // someone else's chain. Closed-taxonomy code matches the page guard.
    throw new AdminAuditLogsError("forbidden", 403);
  }

  const qs = buildVerifyQuery(params, tenantId).toString();
  const path = qs ? `${VERIFY_PATH}?${qs}` : VERIFY_PATH;

  const result = await callAdminBackendJson<unknown>(path, {
    method: "POST",
    headers: {
      "X-Admin-Role": role,
      ...(tenantId ? { "X-Admin-Tenant": tenantId } : {}),
      "X-Operator-Subject": subject,
    },
    body: JSON.stringify({}),
  });

  if (!result.ok) {
    if (result.status === 503) {
      throw new AdminAuditLogsError("network_error", 503);
    }
    throw new AdminAuditLogsError(
      statusToAdminAuditLogsCode(result.status),
      result.status,
    );
  }

  const parsed = AuditChainVerifyResponseSchema.safeParse(result.data);
  if (!parsed.success) {
    throw new AdminAuditLogsError("server_error", 200);
  }
  return parsed.data;
}
