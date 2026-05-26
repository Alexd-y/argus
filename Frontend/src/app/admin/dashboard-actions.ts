"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";

function assertOk<T>(
  result: Awaited<ReturnType<typeof callAdminBackendJson<T>>>,
): T {
  if (result.ok) return result.data;
  throw new Error(result.error);
}

export type HealthDashboard = {
  database: boolean;
  redis: boolean;
  storage: boolean;
  status: "ok" | "degraded";
};

export type LlmRuntimeSummary = {
  execution_uses_global_env: boolean;
  global_env_providers: Record<string, boolean>;
};

export type AuditLogEntry = {
  id: string;
  tenant_id: string | null;
  user_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown> | null;
  created_at: string;
};

export type AdminTenant = {
  id: string;
  name: string;
  created_at: string;
  updated_at: string;
};

export type ScanSummary = {
  scans: Array<{ id: string; status: string; target: string; created_at: string }>;
  total: number;
};

export type FindingsSummary = {
  total: number;
};

export type EmergencyStatus = {
  global_stop_active: boolean;
  tenant_throttles: Record<string, boolean>;
};

export async function getHealthDashboard(): Promise<HealthDashboard> {
  return assertOk(
    await callAdminBackendJson<HealthDashboard>("/health/dashboard", { method: "GET" }),
  );
}

export async function getLlmRuntimeSummary(): Promise<LlmRuntimeSummary> {
  return assertOk(
    await callAdminBackendJson<LlmRuntimeSummary>("/llm/runtime-summary", { method: "GET" }),
  );
}

export async function getRecentAuditLogs(limit: number = 15): Promise<AuditLogEntry[]> {
  return assertOk(
    await callAdminBackendJson<AuditLogEntry[]>(
      `/audit-logs?limit=${limit}&offset=0`,
      { method: "GET" },
    ),
  );
}

export async function getDashboardTenants(): Promise<AdminTenant[]> {
  return assertOk(
    await callAdminBackendJson<AdminTenant[]>("/tenants?limit=100&offset=0", {
      method: "GET",
    }),
  );
}

export async function getDashboardScans(tenantId: string): Promise<ScanSummary> {
  const sp = new URLSearchParams({ tenant_id: tenantId, limit: "50", offset: "0" });
  return assertOk(
    await callAdminBackendJson<ScanSummary>(`/scans?${sp.toString()}`, { method: "GET" }),
  );
}

export async function getDashboardFindingsCount(): Promise<FindingsSummary> {
  const result = assertOk(
    await callAdminBackendJson<{ items: unknown[]; total: number }>(
      "/findings?limit=1&offset=0",
      { method: "GET" },
    ),
  );
  return { total: result.total };
}

export async function getEmergencyStatus(): Promise<EmergencyStatus> {
  return assertOk(
    await callAdminBackendJson<EmergencyStatus>("/system/emergency/status", {
      method: "GET",
    }),
  );
}