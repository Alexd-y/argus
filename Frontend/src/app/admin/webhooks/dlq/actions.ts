"use server";

/**
 * Server actions for the admin **webhook DLQ** surface (T41, ARG-053).
 *
 * Mirrors the canonical pattern established by the schedules / operations
 * / audit-logs actions (Batch 4):
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
 *   - Backend `detail` snake_case tokens (T39 contract) are mapped through
 *     `detailToWebhookDlqActionCode` so the closed taxonomy carries
 *     semantic information (e.g. 409 with `already_replayed` vs the
 *     default `already_replayed`). Raw `detail` strings, stack traces and
 *     PII NEVER cross the action boundary.
 *
 * Backend contract (T39, `backend/src/api/routers/admin_webhook_dlq.py`):
 *
 *   GET    /admin/webhooks/dlq?status=&adapter_name=&created_after=&
 *                              created_before=&limit=&offset=
 *     200   : WebhookDlqListResponse
 *     403   : forbidden / tenant_required
 *
 *   POST   /admin/webhooks/dlq/{entry_id}/replay
 *     202   : WebhookDlqReplayResponse (success=true|false)
 *     404   : dlq_entry_not_found (incl. cross-tenant admin probes)
 *     409   : already_replayed / already_abandoned
 *     422   : validation_failed
 *
 *   POST   /admin/webhooks/dlq/{entry_id}/abandon
 *     200   : WebhookDlqAbandonResponse
 *     404   : dlq_entry_not_found (incl. cross-tenant admin probes)
 *     409   : already_replayed / already_abandoned
 *     422   : validation_failed
 */

import { revalidatePath } from "next/cache";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import { getServerAdminSession } from "@/services/admin/serverSession";
import {
  WEBHOOK_DLQ_LIMIT_DEFAULT,
  WEBHOOK_DLQ_LIMIT_MAX,
  WEBHOOK_DLQ_TRIAGE_STATUSES,
  WebhookDlqAbandonInputSchema,
  WebhookDlqAbandonResponseSchema,
  WebhookDlqActionError,
  WebhookDlqListResponseSchema,
  WebhookDlqReplayInputSchema,
  WebhookDlqReplayResponseSchema,
  detailToWebhookDlqActionCode,
  isUuid,
  statusToWebhookDlqActionCode,
  type WebhookDlqAbandonResponse,
  type WebhookDlqListResponse,
  type WebhookDlqReplayResponse,
  type WebhookDlqTriageStatus,
} from "@/lib/adminWebhookDlq";

const DLQ_PATH = "/webhooks/dlq";
const DLQ_PAGE_PATH = "/admin/webhooks/dlq";

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

type ResolvedSession = {
  readonly role: "admin" | "super-admin";
  readonly tenantId: string | null;
  readonly subject: string;
};

/**
 * Resolve a server session that is allowed to mutate DLQ state.
 *
 * RBAC contract (matches backend `_require_admin_or_super`):
 *   - null role  → 401 unauthorized
 *   - operator   → 403 forbidden
 *   - admin      → own tenant only (server validates again)
 *   - super-admin → any tenant
 */
async function resolveSession(): Promise<ResolvedSession> {
  const session = await getServerAdminSession();
  if (session.role === null) {
    throw new WebhookDlqActionError("unauthorized", 401);
  }
  if (session.role === "operator") {
    throw new WebhookDlqActionError("forbidden", 403);
  }
  return {
    role: session.role,
    tenantId: session.tenantId,
    subject: session.subject,
  };
}

/**
 * Decide which tenant scope to forward to the backend.
 *
 *   - admin       → MUST be scoped to their session tenant; if the caller
 *                   asked for a different tenant we reject as `forbidden`.
 *   - super-admin → honours `callerTenantId`; `null` triggers cross-tenant.
 */
function resolveTenantScope(
  session: ResolvedSession,
  callerTenantId: string | null | undefined,
): string | null {
  if (session.role === "admin") {
    if (!session.tenantId) {
      throw new WebhookDlqActionError("tenant_required", 403);
    }
    if (
      callerTenantId !== undefined &&
      callerTenantId !== null &&
      callerTenantId !== session.tenantId
    ) {
      throw new WebhookDlqActionError("forbidden", 403);
    }
    return session.tenantId;
  }
  const trimmed = (callerTenantId ?? "").trim();
  return trimmed === "" ? null : trimmed;
}

function mapResultToError(result: {
  status: number;
  detail?: unknown;
}): WebhookDlqActionError {
  const fromDetail = detailToWebhookDlqActionCode(result.detail);
  const code = fromDetail ?? statusToWebhookDlqActionCode(result.status);
  return new WebhookDlqActionError(code, result.status);
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
  if (raw === undefined || !Number.isFinite(raw)) {
    return WEBHOOK_DLQ_LIMIT_DEFAULT;
  }
  const n = Math.trunc(raw);
  if (n < 1) return 1;
  if (n > WEBHOOK_DLQ_LIMIT_MAX) return WEBHOOK_DLQ_LIMIT_MAX;
  return n;
}

function normalizeStatusFilter(
  raw: string | null | undefined,
): WebhookDlqTriageStatus | null {
  if (raw == null || raw === "") return null;
  const trimmed = raw.trim().toLowerCase();
  return (WEBHOOK_DLQ_TRIAGE_STATUSES as readonly string[]).includes(trimmed)
    ? (trimmed as WebhookDlqTriageStatus)
    : null;
}

function normalizeIsoDate(raw: string | null | undefined): string | null {
  if (raw == null) return null;
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  // The backend accepts both date-only (YYYY-MM-DD) and full ISO-8601.
  // We forward as-is and let FastAPI parse + reject (422) on bad input.
  // Defence in depth: filter out anything with control characters.
  if (/[\u0000-\u001F\u007F]/.test(trimmed)) return null;
  return trimmed;
}

// ---------------------------------------------------------------------------
// listWebhookDlqAction — GET /admin/webhooks/dlq
// ---------------------------------------------------------------------------

export type ListWebhookDlqInput = {
  readonly tenantId?: string | null;
  readonly status?: WebhookDlqTriageStatus | null;
  readonly adapterName?: string | null;
  readonly createdAfter?: string | null;
  readonly createdBefore?: string | null;
  readonly limit?: number;
  readonly offset?: number;
};

/**
 * Paginated list of webhook DLQ entries. admin+ only (operator → 403).
 *
 * @throws {@link WebhookDlqActionError} on RBAC, transport, or schema drift.
 */
export async function listWebhookDlqAction(
  input: ListWebhookDlqInput = {},
): Promise<WebhookDlqListResponse> {
  const session = await resolveSession();
  const effectiveTenantId = resolveTenantScope(session, input.tenantId);

  const limit = clampLimit(input.limit);
  const offset = Math.max(0, Math.trunc(input.offset ?? 0));
  const status = normalizeStatusFilter(input.status ?? null);
  const adapter =
    typeof input.adapterName === "string" && input.adapterName.trim() !== ""
      ? input.adapterName.trim()
      : undefined;
  const createdAfter = normalizeIsoDate(input.createdAfter ?? null);
  const createdBefore = normalizeIsoDate(input.createdBefore ?? null);

  const path = `${DLQ_PATH}${buildQuery({
    status: status ?? undefined,
    adapter_name: adapter,
    created_after: createdAfter ?? undefined,
    created_before: createdBefore ?? undefined,
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

  const parsed = WebhookDlqListResponseSchema.safeParse(result.data);
  if (!parsed.success) {
    throw new WebhookDlqActionError("server_error", 200);
  }
  return parsed.data;
}

// ---------------------------------------------------------------------------
// replayWebhookDlqAction — POST /admin/webhooks/dlq/{entry_id}/replay
// ---------------------------------------------------------------------------

/**
 * Re-dispatch a single DLQ entry. admin+ only.
 *
 * The backend always returns 202; `success=false` + `message_code=
 * "replay_failed"` is a NORMAL outcome (the entry stays in the DLQ).
 * The caller must inspect the response body, NOT the HTTP status, to
 * decide how to render the result.
 *
 * @throws {@link WebhookDlqActionError} with closed-taxonomy codes:
 *   - `unauthorized`, `forbidden`, `tenant_required`, `tenant_mismatch`
 *   - `dlq_entry_not_found` (incl. cross-tenant existence-leak protection)
 *   - `already_replayed`, `already_abandoned`
 *   - `validation_failed`, `rate_limited`
 *   - `store_unavailable`, `server_error`
 */
export async function replayWebhookDlqAction(
  entryId: string,
  rawInput: unknown,
): Promise<WebhookDlqReplayResponse> {
  const session = await resolveSession();

  if (!isUuid(entryId)) {
    throw new WebhookDlqActionError("validation_failed", 400);
  }

  const parsed = WebhookDlqReplayInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new WebhookDlqActionError("validation_failed", 400);
  }

  const result = await callAdminBackendJson<unknown>(
    `${DLQ_PATH}/${encodeURIComponent(entryId)}/replay`,
    {
      method: "POST",
      headers: {
        "X-Admin-Role": session.role,
        ...(session.tenantId
          ? { "X-Admin-Tenant": session.tenantId }
          : {}),
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify({ reason: parsed.data.reason }),
    },
  );

  if (!result.ok) {
    throw mapResultToError(result);
  }

  const parsedBody = WebhookDlqReplayResponseSchema.safeParse(result.data);
  if (!parsedBody.success) {
    throw new WebhookDlqActionError("server_error", 200);
  }

  revalidatePath(DLQ_PAGE_PATH);
  return parsedBody.data;
}

// ---------------------------------------------------------------------------
// abandonWebhookDlqAction — POST /admin/webhooks/dlq/{entry_id}/abandon
// ---------------------------------------------------------------------------

/**
 * Mark a single DLQ entry as terminally abandoned. admin+ only.
 *
 * The free-text `reason` is recorded in the audit row (NOT in the
 * persisted `abandoned_reason` enum, which is always `"operator"`).
 *
 * @throws {@link WebhookDlqActionError} with closed-taxonomy codes (same
 * set as {@link replayWebhookDlqAction}, minus `replay_failed` which is
 * not applicable to the abandon path).
 */
export async function abandonWebhookDlqAction(
  entryId: string,
  rawInput: unknown,
): Promise<WebhookDlqAbandonResponse> {
  const session = await resolveSession();

  if (!isUuid(entryId)) {
    throw new WebhookDlqActionError("validation_failed", 400);
  }

  const parsed = WebhookDlqAbandonInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new WebhookDlqActionError("validation_failed", 400);
  }

  const result = await callAdminBackendJson<unknown>(
    `${DLQ_PATH}/${encodeURIComponent(entryId)}/abandon`,
    {
      method: "POST",
      headers: {
        "X-Admin-Role": session.role,
        ...(session.tenantId
          ? { "X-Admin-Tenant": session.tenantId }
          : {}),
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify({ reason: parsed.data.reason }),
    },
  );

  if (!result.ok) {
    throw mapResultToError(result);
  }

  const parsedBody = WebhookDlqAbandonResponseSchema.safeParse(result.data);
  if (!parsedBody.success) {
    throw new WebhookDlqActionError("server_error", 200);
  }

  revalidatePath(DLQ_PAGE_PATH);
  return parsedBody.data;
}
