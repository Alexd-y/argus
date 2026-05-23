"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import { getServerAdminSession } from "@/services/admin/serverSession";

export type AdminReportSort =
  | "created_at_desc"
  | "created_at_asc"
  | "target_asc"
  | "target_desc";

export type AdminReportListItem = {
  id: string;
  tenant_id: string;
  scan_id: string | null;
  target: string;
  tier: string;
  generation_status: string;
  requested_formats: string[] | null;
  version: number;
  parent_report_id: string | null;
  assigned_to: string | null;
  compliance_tags: string[] | null;
  severity_counts: Record<string, number> | null;
  created_at: string;
};

export type AdminReportListResult = {
  reports: AdminReportListItem[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
};

export type AdminReportDetail = {
  id: string;
  tenant_id: string;
  scan_id: string | null;
  target: string;
  tier: string;
  generation_status: string;
  requested_formats: string[] | null;
  created_at: string;
  summary: Record<string, number> | null;
  technologies: string[] | null;
  available_formats: string[];
  findings_count: number;
  last_error_message: string | null;
  version: number;
  parent_report_id: string | null;
  assigned_to: string | null;
  compliance_tags: string[] | null;
  severity_counts: Record<string, number> | null;
};

export type AdminReportDownloadResult = {
  report_id: string;
  format: string;
  download_url: string | null;
  size_bytes: number | null;
};

export type ReportShareLink = {
  id: string;
  report_id: string;
  token: string;
  share_url: string | null;
  expires_at: string;
  created_by: string | null;
  view_count: number;
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

export async function listAdminReports(params: {
  tenantId: string;
  offset?: number;
  limit?: number;
  sort?: AdminReportSort;
  status?: string;
  tier?: string;
  q?: string;
  since?: string;
  until?: string;
}): Promise<AdminReportListResult> {
  const sp = new URLSearchParams();
  sp.set("tenant_id", params.tenantId);
  sp.set("offset", String(params.offset ?? 0));
  sp.set("limit", String(params.limit ?? 50));
  sp.set("sort", params.sort ?? "created_at_desc");
  if (params.status?.trim()) sp.set("status", params.status.trim());
  if (params.tier?.trim()) sp.set("tier", params.tier.trim());
  if (params.q?.trim()) sp.set("q", params.q.trim());
  if (params.since) sp.set("since", params.since);
  if (params.until) sp.set("until", params.until);
  const result = await callAdminBackendJson<AdminReportListResult>(
    `/reports?${sp.toString()}`,
    { method: "GET" },
  );
  return assertOk(result);
}

export async function getAdminReportDetail(
  tenantId: string,
  reportId: string,
): Promise<AdminReportDetail> {
  const sp = new URLSearchParams();
  sp.set("tenant_id", tenantId);
  const result = await callAdminBackendJson<AdminReportDetail>(
    `/reports/${enc(reportId)}?${sp.toString()}`,
    { method: "GET" },
  );
  return assertOk(result);
}

export async function generateAdminReport(input: {
  tenantId: string;
  scanId: string;
  tier: string;
  formats: string[];
  assignedTo?: string;
  complianceTags?: string[];
  executiveSummary?: string;
  parentReportId?: string;
}): Promise<{ report_id: string; status: string }> {
  const session = await getServerAdminSession();
  if (!session.role || session.role === "operator") {
    throw new Error("Insufficient permissions");
  }

  const effectiveTenantId =
    session.role === "super-admin"
      ? input.tenantId
      : (session.tenantId ?? input.tenantId);

  const result = await callAdminBackendJson<{ report_id: string; status: string }>(
    "/reports/generate",
    {
      method: "POST",
      headers: {
        "X-Admin-Role": session.role,
        "X-Admin-Tenant": effectiveTenantId,
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify({
        tenant_id: effectiveTenantId,
        scan_id: input.scanId,
        target: "",
        tier: input.tier,
        formats: input.formats,
        ...(input.assignedTo ? { assigned_to: input.assignedTo } : {}),
        ...(input.complianceTags?.length
          ? { compliance_tags: input.complianceTags }
          : {}),
        ...(input.executiveSummary
          ? { executive_summary: input.executiveSummary }
          : {}),
        ...(input.parentReportId
          ? { parent_report_id: input.parentReportId }
          : {}),
      }),
    },
  );
  return assertOk(result);
}

export async function regenerateAdminReport(
  tenantId: string,
  reportId: string,
  formats?: string[],
): Promise<{ report_id: string; parent_report_id: string | null; version: number; status: string }> {
  const session = await getServerAdminSession();
  if (!session.role || session.role === "operator") {
    throw new Error("Insufficient permissions");
  }

  const effectiveTenantId =
    session.role === "super-admin"
      ? tenantId
      : (session.tenantId ?? tenantId);

  const sp = new URLSearchParams();
  sp.set("tenant_id", effectiveTenantId);

  const result = await callAdminBackendJson<{
    report_id: string;
    parent_report_id: string | null;
    version: number;
    status: string;
  }>(
    `/reports/${enc(reportId)}/regenerate?${sp.toString()}`,
    {
      method: "POST",
      headers: {
        "X-Admin-Role": session.role,
        "X-Admin-Tenant": effectiveTenantId,
        "X-Operator-Subject": session.subject,
      },
      body: formats ? JSON.stringify({ formats }) : "{}",
    },
  );
  return assertOk(result);
}

export async function downloadAdminReport(
  tenantId: string,
  reportId: string,
  format: string,
): Promise<AdminReportDownloadResult> {
  const sp = new URLSearchParams();
  sp.set("tenant_id", tenantId);
  const result = await callAdminBackendJson<AdminReportDownloadResult>(
    `/reports/${enc(reportId)}/download/${enc(format)}?${sp.toString()}`,
    { method: "GET" },
  );
  return assertOk(result);
}

export async function createShareLink(
  tenantId: string,
  reportId: string,
  expiresInDays: number = 7,
): Promise<ReportShareLink> {
  const session = await getServerAdminSession();
  if (!session.role || session.role === "operator") {
    throw new Error("Insufficient permissions");
  }

  const effectiveTenantId =
    session.role === "super-admin"
      ? tenantId
      : (session.tenantId ?? tenantId);

  const sp = new URLSearchParams();
  sp.set("tenant_id", effectiveTenantId);

  const result = await callAdminBackendJson<ReportShareLink>(
    `/reports/${enc(reportId)}/share-links?${sp.toString()}`,
    {
      method: "POST",
      headers: {
        "X-Admin-Role": session.role,
        "X-Admin-Tenant": effectiveTenantId,
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify({
        report_id: reportId,
        expires_in_days: expiresInDays,
        created_by: session.subject,
      }),
    },
  );
  return assertOk(result);
}

export async function listShareLinks(
  tenantId: string,
  reportId: string,
): Promise<ReportShareLink[]> {
  const sp = new URLSearchParams();
  sp.set("tenant_id", tenantId);
  const result = await callAdminBackendJson<ReportShareLink[]>(
    `/reports/${enc(reportId)}/share-links?${sp.toString()}`,
    { method: "GET" },
  );
  return assertOk(result);
}

export async function deleteShareLink(
  tenantId: string,
  reportId: string,
  linkId: string,
): Promise<void> {
  const session = await getServerAdminSession();
  if (!session.role || session.role === "operator") {
    throw new Error("Insufficient permissions");
  }

  const effectiveTenantId =
    session.role === "super-admin"
      ? tenantId
      : (session.tenantId ?? tenantId);

  const sp = new URLSearchParams();
  sp.set("tenant_id", effectiveTenantId);

  const result = await callAdminBackendJson<unknown>(
    `/reports/${enc(reportId)}/share-links/${enc(linkId)}?${sp.toString()}`,
    {
      method: "DELETE",
      headers: {
        "X-Admin-Role": session.role,
        "X-Admin-Tenant": effectiveTenantId,
        "X-Operator-Subject": session.subject,
      },
    },
  );
  if (!result.ok) throw new Error(result.error);
}