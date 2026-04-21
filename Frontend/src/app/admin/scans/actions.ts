"use server";

import {
  KillScanInputSchema,
  ScanActionError,
  isUuid,
  statusToScanActionCode,
  type KillScanInput,
  type KillScanResult,
} from "@/lib/adminScans";
import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import { getServerAdminSession } from "@/services/admin/serverSession";

export type AdminScanSort = "created_at_desc" | "created_at_asc";

export type AdminScanListItem = {
  id: string;
  status: string;
  progress: number;
  phase: string;
  target: string;
  created_at: string;
  updated_at: string;
  scan_mode: string;
};

export type AdminScanListResult = {
  scans: AdminScanListItem[];
  total: number;
  limit: number;
  offset: number;
};

export type AdminScanToolMetric = {
  tool_name: string;
  status: string;
  duration_sec: number | null;
  started_at: string | null;
  finished_at: string | null;
};

export type AdminScanErrorItem = {
  at: string;
  phase: string | null;
  message: string;
};

export type AdminScanDetail = {
  id: string;
  status: string;
  progress: number;
  phase: string;
  target: string;
  created_at: string;
  updated_at: string;
  scan_mode: string;
  tool_metrics: AdminScanToolMetric[];
  error_summary: AdminScanErrorItem[];
};

export type BulkScanCancelItemStatus = "cancelled" | "skipped_terminal" | "not_found";

export type AdminBulkScanCancelResponse = {
  cancelled_count: number;
  skipped_terminal_count: number;
  not_found_count: number;
  audit_id: string;
  results: { scan_id: string; status: BulkScanCancelItemStatus }[];
};

function assertOk<T>(
  result: Awaited<ReturnType<typeof callAdminBackendJson<T>>>,
): T {
  if (result.ok) return result.data;
  throw new Error(result.error);
}

function enc(s: string): string {
  return encodeURIComponent(s);
}

export async function listAdminScans(params: {
  tenantId: string;
  offset?: number;
  limit?: number;
  sort?: AdminScanSort;
  status?: string;
}): Promise<AdminScanListResult> {
  const sp = new URLSearchParams();
  sp.set("tenant_id", params.tenantId);
  sp.set("offset", String(params.offset ?? 0));
  sp.set("limit", String(params.limit ?? 50));
  sp.set("sort", params.sort ?? "created_at_desc");
  if (params.status?.trim()) sp.set("status", params.status.trim());
  const result = await callAdminBackendJson<AdminScanListResult>(`/scans?${sp.toString()}`, {
    method: "GET",
  });
  return assertOk(result);
}

export async function getAdminScanDetail(
  tenantId: string,
  scanId: string,
): Promise<AdminScanDetail> {
  const sp = new URLSearchParams();
  sp.set("tenant_id", tenantId);
  const result = await callAdminBackendJson<AdminScanDetail>(
    `/scans/${enc(scanId)}?${sp.toString()}`,
    { method: "GET" },
  );
  return assertOk(result);
}

export async function bulkCancelAdminScans(
  tenantId: string,
  scanIds: string[],
): Promise<AdminBulkScanCancelResponse> {
  const unique = [...new Set(scanIds.filter((id) => id && id.trim()))];
  if (unique.length === 0) {
    throw new Error("Select at least one scan.");
  }
  const result = await callAdminBackendJson<AdminBulkScanCancelResponse>(`/scans/bulk-cancel`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: tenantId, scan_ids: unique }),
  });
  return assertOk(result);
}

/**
 * Per-scan kill-switch (T28). Admin / super-admin only.
 *
 * Backend reuse:
 *   The plan called for `POST /scans/{id}/cancel` (the public endpoint).
 *   That route lives outside `/admin/*`, does not enforce `require_admin`,
 *   and crucially has NO request body — so it cannot record the operator
 *   reason. The `callAdminBackendJson` helper is also hard-wired to
 *   `/api/v1/admin`. Rather than introduce a new backend endpoint (the
 *   batch's hard "no new backend" rule), this action funnels through the
 *   existing `POST /admin/scans/bulk-cancel` with a single-element list:
 *     • same RBAC (`require_admin`),
 *     • same audit emit (`bulk_scan_cancel` row with operator subject),
 *     • idempotent terminal-status handling on the backend side.
 *   The operator reason is captured for the structured server-action log
 *   only; ISS-T28-001 tracks adding `reason` to the backend payload.
 *
 * Identity:
 *   - `X-Admin-Role` / `X-Admin-Tenant` / `X-Operator-Subject` come from
 *     `getServerAdminSession()` (cookies + dev env), never from the
 *     caller — the browser cannot widen its own privileges.
 *   - `admin` operators are pinned to their session tenant; mismatching
 *     `tenantId` from the page state is rejected as `forbidden`.
 *   - `super-admin` may target any tenant.
 *
 * The thrown errors are always `ScanActionError` instances with a code
 * from `SCAN_ACTION_FAILURE_TAXONOMY`. The dialog renders the matching
 * RU sentence via `scanActionErrorMessage`; it never echoes raw backend
 * `detail`, stack frames, or PII.
 */
export async function cancelAdminScan(
  rawInput: KillScanInput,
): Promise<KillScanResult> {
  const parsed = KillScanInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new ScanActionError("validation_failed", 400);
  }
  const input = parsed.data;

  const session = await getServerAdminSession();
  if (session.role === null) {
    throw new ScanActionError("unauthorized", 401);
  }
  if (session.role === "operator") {
    throw new ScanActionError("forbidden", 403);
  }

  const effectiveTenantId =
    session.role === "super-admin"
      ? input.tenantId
      : (session.tenantId ?? null);

  if (!effectiveTenantId || !isUuid(effectiveTenantId)) {
    throw new ScanActionError("forbidden", 403);
  }
  if (session.role === "admin" && effectiveTenantId !== input.tenantId) {
    throw new ScanActionError("forbidden", 403);
  }

  const result = await callAdminBackendJson<AdminBulkScanCancelResponse>(
    `/scans/bulk-cancel`,
    {
      method: "POST",
      headers: {
        "X-Admin-Role": session.role,
        "X-Admin-Tenant": effectiveTenantId,
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify({
        tenant_id: effectiveTenantId,
        scan_ids: [input.scanId],
      }),
    },
  );

  if (!result.ok) {
    throw new ScanActionError(
      statusToScanActionCode(result.status),
      result.status,
    );
  }

  const data = result.data;
  if (
    data == null ||
    typeof data !== "object" ||
    !Array.isArray(data.results)
  ) {
    throw new ScanActionError("server_error", 200);
  }

  const item = data.results.find((r) => r.scan_id === input.scanId);
  if (!item) {
    // Backend lost track of our id but still returned 200 — treat as
    // schema drift to avoid a silent success in the UI.
    throw new ScanActionError("server_error", 200);
  }

  const validStatuses: ReadonlyArray<KillScanResult["status"]> = [
    "cancelled",
    "skipped_terminal",
    "not_found",
  ];
  if (!validStatuses.includes(item.status as KillScanResult["status"])) {
    throw new ScanActionError("server_error", 200);
  }

  return {
    status: item.status as KillScanResult["status"],
    scanId: input.scanId,
    auditId: typeof data.audit_id === "string" ? data.audit_id : null,
  };
}
