"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import type { PdfArchivalFormat } from "@/app/admin/tenants/types";

export type AdminTenant = {
  id: string;
  name: string;
  exports_sarif_junit_enabled: boolean;
  rate_limit_rpm: number | null;
  scope_blacklist: string[] | null;
  retention_days: number | null;
  pdf_archival_format: PdfArchivalFormat;
  created_at: string;
  updated_at: string;
};

export type TenantCreateBody = { name: string };

export type TenantPatchBody = {
  name?: string;
  exports_sarif_junit_enabled?: boolean;
  rate_limit_rpm?: number | null;
  scope_blacklist?: string[] | null;
  retention_days?: number | null;
  pdf_archival_format?: PdfArchivalFormat;
};

function assertOk<T>(
  result: Awaited<ReturnType<typeof callAdminBackendJson<T>>>,
): T {
  if (result.ok) return result.data;
  throw new Error(result.error);
}

export async function getTenant(tenantId: string): Promise<AdminTenant | null> {
  const enc = encodeURIComponent(tenantId);
  const result = await callAdminBackendJson<AdminTenant>(`/tenants/${enc}`, {
    method: "GET",
  });
  if (result.ok) return result.data;
  if (result.status === 404) return null;
  throw new Error(result.error);
}

export async function listTenants(
  params: { limit?: number; offset?: number } = {},
): Promise<AdminTenant[]> {
  const sp = new URLSearchParams();
  if (params.limit != null) sp.set("limit", String(params.limit));
  if (params.offset != null) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  const path = qs ? `/tenants?${qs}` : "/tenants";
  const result = await callAdminBackendJson<AdminTenant[]>(path, {
    method: "GET",
  });
  return assertOk(result);
}

export async function createTenant(body: TenantCreateBody): Promise<AdminTenant> {
  const result = await callAdminBackendJson<AdminTenant>("/tenants", {
    method: "POST",
    body: JSON.stringify(body),
  });
  return assertOk(result);
}

export async function updateTenant(
  tenantId: string,
  body: TenantPatchBody,
): Promise<AdminTenant> {
  const enc = encodeURIComponent(tenantId);
  const result = await callAdminBackendJson<AdminTenant>(`/tenants/${enc}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
  return assertOk(result);
}

export async function deleteTenant(tenantId: string): Promise<void> {
  const enc = encodeURIComponent(tenantId);
  const result = await callAdminBackendJson<void>(`/tenants/${enc}`, {
    method: "DELETE",
  });
  assertOk(result);
}
