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
  statusToAdminFindingsCode,
  type AdminFindingsListResponse,
  type ListAdminFindingsParams,
} from "@/lib/adminFindings";
import { getServerAdminSession } from "@/services/admin/serverSession";

const FINDINGS_PATH = "/findings";

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
