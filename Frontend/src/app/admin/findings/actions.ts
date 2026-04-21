"use server";

/**
 * Server actions for the cross-tenant findings triage console (T20).
 *
 * Why a server action:
 *   The admin endpoints require `X-Admin-Key` (per `require_admin` in
 *   `backend/src/api/routers/admin.py`). That key MUST never reach the browser
 *   — see `Frontend/src/app/api/admin/tenants/route.ts` which deliberately
 *   returns HTTP 410 to enforce this pattern. Routing the request through a
 *   `"use server"` action lets `callAdminBackendJson` attach the key from a
 *   server-only env var (`ADMIN_API_KEY`) while keeping the React Query call
 *   site essentially unchanged.
 *
 * Identity propagation:
 *   `X-Admin-Role` / `X-Admin-Tenant` / `X-Operator-Subject` are resolved
 *   from `getServerAdminSession()` rather than from action arguments — the
 *   browser cannot widen its own privileges by passing different values.
 */

import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import {
  AdminFindingsError,
  AdminFindingsListResponseSchema,
  BackendBulkSuppressResponseSchema,
  BulkFindingsActionError,
  buildBulkSuppressReason,
  groupBulkTargetsByTenant,
  isBulkSuppressReason,
  isUuid,
  MAX_BULK_FINDING_IDS,
  statusToAdminFindingsCode,
  statusToBulkFailureCode,
  type AdminFindingsListResponse,
  type BulkActionResult,
  type BulkFailureCode,
  type BulkFindingTarget,
  type BulkSuppressReason,
  type ListAdminFindingsParams,
} from "@/lib/adminFindings";
import { getServerAdminSession } from "@/services/admin/serverSession";

const FINDINGS_PATH = "/findings";
const BULK_SUPPRESS_PATH = "/findings/bulk-suppress";

/**
 * Build the FastAPI-side query string from a typed parameter bag. The wire
 * names (`q`, `false_positive`, `kev_listed`, `ssvc_action`) match
 * `backend/src/api/routers/admin_findings.py::admin_list_findings`.
 *
 * Reserved Phase-2 params (`kev_listed`, `ssvc_action`) are only included
 * when the caller explicitly sets them — sending `null` would push the
 * backend onto the deprecated branch even when the operator never touched
 * the chip.
 */
function buildFindingsQuery(
  params: ListAdminFindingsParams,
  effectiveTenantId: string | null,
): URLSearchParams {
  const sp = new URLSearchParams();

  if (effectiveTenantId && effectiveTenantId.trim()) {
    sp.set("tenant_id", effectiveTenantId.trim());
  }

  for (const sev of params.severity ?? []) {
    sp.append("severity", sev);
  }

  // status_ui (UI tri-state) → backend `false_positive` (bool|undefined)
  if (params.statusMode === "open") sp.set("false_positive", "false");
  else if (params.statusMode === "false_positive")
    sp.set("false_positive", "true");

  if (params.target && params.target.trim()) {
    sp.set("q", params.target.trim());
  }

  if (params.since) sp.set("since", params.since);
  if (params.until) sp.set("until", params.until);

  // The backend is offset/limit-paginated today; we treat `cursor` as a
  // numeric offset string so the React Query `getNextPageParam` flow stays
  // a single primitive.
  if (params.cursor) {
    const offset = Number.parseInt(params.cursor, 10);
    if (Number.isFinite(offset) && offset >= 0) {
      sp.set("offset", String(offset));
    }
  }
  if (params.limit != null) sp.set("limit", String(params.limit));

  if (params.kevListed === true) sp.set("kev_listed", "true");
  if (params.kevListed === false) sp.set("kev_listed", "false");
  if (params.ssvcAction) sp.set("ssvc_action", params.ssvcAction);

  return sp;
}

/**
 * Fetch a single page of admin findings.
 *
 * The action:
 *   - resolves the operator's identity from the server session (NEVER from
 *     action arguments — that would be client-injectable);
 *   - refuses cross-tenant queries from `admin` operators that don't have a
 *     bound tenant (returns an empty page so the UI renders the empty state
 *     instead of leaking other tenants' data);
 *   - validates the response with Zod and throws `AdminFindingsError` on
 *     schema mismatch / transport failure (closed-taxonomy: the browser only
 *     ever sees `unauthorized | forbidden | rate_limited | invalid_input |
 *     server_error | network_error`).
 */
export async function listAdminFindingsAction(
  params: ListAdminFindingsParams = {},
): Promise<AdminFindingsListResponse> {
  const session = await getServerAdminSession();

  if (session.role === null) {
    throw new AdminFindingsError("unauthorized", 401);
  }

  // Tenant resolution — `admin` is bound to its session tenant; `super-admin`
  // may pick (or omit for cross-tenant view) via the URL.
  let effectiveTenantId: string | null;
  if (session.role === "super-admin") {
    effectiveTenantId =
      params.tenantId && params.tenantId.trim()
        ? params.tenantId.trim()
        : null;
  } else {
    if (!session.tenantId) {
      // Defensive: action should not be invoked in this case (the page
      // renders an empty state and skips the query for `enabled: false`).
      // If something does invoke us, return an empty page rather than
      // bubbling raw 4xx noise to the React Query retry loop.
      return AdminFindingsListResponseSchema.parse({
        items: [],
        total: 0,
        limit: params.limit ?? 0,
        offset: 0,
        has_more: false,
        next_cursor: null,
      });
    }
    effectiveTenantId = session.tenantId;
  }

  const qs = buildFindingsQuery(params, effectiveTenantId).toString();
  const path = qs ? `${FINDINGS_PATH}?${qs}` : FINDINGS_PATH;

  const result = await callAdminBackendJson<unknown>(path, {
    method: "GET",
    headers: {
      "X-Admin-Role": session.role,
      ...(effectiveTenantId ? { "X-Admin-Tenant": effectiveTenantId } : {}),
      "X-Operator-Subject": session.subject,
    },
  });

  if (!result.ok) {
    if (result.status === 503) {
      // 503 surfaces both transport failure and "ADMIN_API_KEY missing" —
      // both look like "service unreachable" to the operator.
      throw new AdminFindingsError("network_error", 503);
    }
    throw new AdminFindingsError(
      statusToAdminFindingsCode(result.status),
      result.status,
    );
  }

  const parsed = AdminFindingsListResponseSchema.safeParse(result.data);
  if (!parsed.success) {
    // Schema mismatch is a server contract drift, not a user error — keep
    // the closed taxonomy and never echo Zod issue paths to the browser.
    throw new AdminFindingsError("server_error", 200);
  }
  return parsed.data;
}

// ────────────────────────────────────────────────────────────────────────────
// Bulk findings actions (T21)
//
// Backend contract: ONLY `POST /admin/findings/bulk-suppress` is wired today.
// Both "suppress" and "mark false positive" funnel through this endpoint —
// the difference is the `reason` payload (operator taxonomy vs. fixed
// `false_positive` literal) so audit logs can distinguish them.
//
// Phase-2 actions (`escalate`, `attach_to_cve`) have NO backend support yet —
// the UI surfaces them as disabled buttons with deferred-issue tooltips
// (ISS-T21-001 / ISS-T21-002). Server actions for them are intentionally
// omitted to avoid silent no-ops.
// ────────────────────────────────────────────────────────────────────────────

/**
 * Resolve the operator session and refuse the bulk write upfront for
 * roles that have no business mutating findings (`operator`) or whose
 * session is not signed in (`null`). Returns the role + subject the
 * caller will forward to the backend.
 */
async function resolveBulkSession(): Promise<{
  role: "admin" | "super-admin";
  tenantId: string | null;
  subject: string;
}> {
  const session = await getServerAdminSession();
  if (session.role === null) {
    throw new BulkFindingsActionError("unauthorized", 401);
  }
  if (session.role === "operator") {
    throw new BulkFindingsActionError("forbidden", 403);
  }
  return {
    role: session.role,
    tenantId: session.tenantId,
    subject: session.subject,
  };
}

/**
 * Pre-flight validation shared by every bulk action:
 *   - reject empty / over-cap selections (hard backend limit is 100);
 *   - reject targets whose ids/tenants are not UUIDs (defensive — the
 *     browser shouldn't be able to feed garbage into a write path);
 *   - for `admin` role, refuse cross-tenant selections outright (the
 *     operator can only act on their bound tenant).
 */
function validateAndGroup(
  role: "admin" | "super-admin",
  sessionTenantId: string | null,
  targets: ReadonlyArray<BulkFindingTarget>,
): {
  grouped: ReadonlyMap<string, ReadonlyArray<string>>;
  preFlightSkipped: ReadonlyArray<string>;
} {
  if (targets.length === 0) {
    throw new BulkFindingsActionError("validation_failed", 400);
  }
  if (targets.length > MAX_BULK_FINDING_IDS) {
    throw new BulkFindingsActionError("validation_failed", 400);
  }

  const { grouped, skipped } = groupBulkTargetsByTenant(targets);

  if (role === "admin") {
    if (sessionTenantId === null || !isUuid(sessionTenantId)) {
      throw new BulkFindingsActionError("forbidden", 403);
    }
    // Admin: every selected item must belong to the session-bound tenant.
    // We never send another tenant's ids to the backend, even by accident.
    for (const tid of grouped.keys()) {
      if (tid !== sessionTenantId) {
        throw new BulkFindingsActionError("forbidden", 403);
      }
    }
  }

  return { grouped, preFlightSkipped: skipped };
}

/**
 * Issue one `POST /admin/findings/bulk-suppress` per tenant in the grouped
 * map and aggregate the per-tenant envelopes into a single
 * {@link BulkActionResult}. The first tenant-level failure wins for
 * `failure_reason_taxonomy`; partial failures across other tenants still
 * surface in `failed_ids`.
 */
async function fanOutBulkSuppress(
  grouped: ReadonlyMap<string, ReadonlyArray<string>>,
  reasonString: string,
  role: "admin" | "super-admin",
  subject: string,
  preFlightSkipped: ReadonlyArray<string>,
): Promise<BulkActionResult> {
  let totalSuppressed = 0;
  let totalSkipped = 0;
  const failedIds: string[] = [...preFlightSkipped];
  const auditIds: string[] = [];
  let firstFailureCode: BulkFailureCode | null = null;

  for (const [tenantId, ids] of grouped) {
    if (ids.length === 0) continue;

    const result = await callAdminBackendJson<unknown>(BULK_SUPPRESS_PATH, {
      method: "POST",
      headers: {
        "X-Admin-Role": role,
        "X-Admin-Tenant": tenantId,
        "X-Operator-Subject": subject,
      },
      body: JSON.stringify({
        tenant_id: tenantId,
        finding_ids: ids,
        reason: reasonString,
      }),
    });

    if (!result.ok) {
      const code = statusToBulkFailureCode(result.status);
      if (firstFailureCode === null) firstFailureCode = code;
      // The backend wrote nothing for this tenant — every selected id is a
      // "failed" id from the operator's POV.
      failedIds.push(...ids);
      continue;
    }

    const parsed = BackendBulkSuppressResponseSchema.safeParse(result.data);
    if (!parsed.success) {
      if (firstFailureCode === null) firstFailureCode = "server_error";
      failedIds.push(...ids);
      continue;
    }

    totalSuppressed += parsed.data.suppressed_count;
    totalSkipped += parsed.data.skipped_already_suppressed_count;
    auditIds.push(parsed.data.audit_id);
    for (const item of parsed.data.results) {
      if (item.status === "not_found") {
        failedIds.push(item.finding_id);
      }
    }
  }

  return {
    affected_count: totalSuppressed,
    skipped_count: totalSkipped,
    failed_ids: failedIds,
    failure_reason_taxonomy: firstFailureCode,
    audit_ids: auditIds,
  };
}

export type BulkSuppressFindingsParams = {
  readonly targets: ReadonlyArray<BulkFindingTarget>;
  readonly reason: BulkSuppressReason;
  readonly comment?: string | null;
};

/**
 * Operator-driven suppression (open taxonomy of business reasons). The
 * action ALWAYS funnels through the backend's `bulk-suppress` endpoint
 * because that is the only mutation primitive available today; the
 * `reason` string carries the closed taxonomy + optional comment so audit
 * trails can distinguish it from a `mark_false_positive` write.
 */
export async function bulkSuppressFindingsAction(
  params: BulkSuppressFindingsParams,
): Promise<BulkActionResult> {
  if (!isBulkSuppressReason(params.reason)) {
    throw new BulkFindingsActionError("validation_failed", 400);
  }

  const { role, tenantId, subject } = await resolveBulkSession();
  const { grouped, preFlightSkipped } = validateAndGroup(
    role,
    tenantId,
    params.targets,
  );

  const reasonString = buildBulkSuppressReason(params.reason, params.comment);

  return fanOutBulkSuppress(
    grouped,
    reasonString,
    role,
    subject,
    preFlightSkipped,
  );
}

export type BulkMarkFalsePositiveParams = {
  readonly targets: ReadonlyArray<BulkFindingTarget>;
  readonly comment?: string | null;
};

/**
 * "Mark as false positive" — semantically distinct from a generic
 * suppression because it asserts the finding is wrong, not just
 * deprioritised. We pin the backend `reason` to the literal
 * `"false_positive"` so downstream tooling (audit log filter, dedup
 * dashboard) can route it differently.
 */
export async function bulkMarkFalsePositiveFindingsAction(
  params: BulkMarkFalsePositiveParams,
): Promise<BulkActionResult> {
  const { role, tenantId, subject } = await resolveBulkSession();
  const { grouped, preFlightSkipped } = validateAndGroup(
    role,
    tenantId,
    params.targets,
  );

  const reasonString = buildBulkSuppressReason(
    "false_positive",
    params.comment,
  );

  return fanOutBulkSuppress(
    grouped,
    reasonString,
    role,
    subject,
    preFlightSkipped,
  );
}
