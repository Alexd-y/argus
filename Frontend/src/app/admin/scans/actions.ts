"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";

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
