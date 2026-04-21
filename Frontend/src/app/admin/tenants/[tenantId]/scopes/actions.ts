"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";

export type OwnershipProofStatus = {
  lookup_available: boolean;
  verified: boolean | null;
  policy_requires_proof: boolean | null;
};

export type AdminScopeTarget = {
  id: string;
  tenant_id: string;
  url: string;
  scope_config: { rules?: Record<string, unknown>[] } | null;
  created_at: string;
  ownership_proof: OwnershipProofStatus;
};

export type TargetCreateBody = {
  url: string;
  scope_config: { rules: Record<string, unknown>[] } | null;
};

export type TargetPatchBody = {
  url?: string;
  scope_config: { rules: Record<string, unknown>[] } | null;
};

export type PreviewScopeBody = {
  probe: string;
  rules: Record<string, unknown>[];
  port?: number | null;
  dns_hostname?: string | null;
  cidr?: string | null;
};

export type PreviewScopeResult = {
  scope_allowed: boolean;
  scope_failure_summary: string | null;
  dns: {
    hostname: string | null;
    addresses: string[];
    error: string | null;
  } | null;
  cidr: {
    network: string;
    address_total: string | null;
    sample: string[];
  } | null;
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

export async function listScopeTargets(
  tenantId: string,
): Promise<AdminScopeTarget[]> {
  const result = await callAdminBackendJson<AdminScopeTarget[]>(
    `/tenants/${enc(tenantId)}/targets`,
    { method: "GET" },
  );
  return assertOk(result);
}

export async function createScopeTarget(
  tenantId: string,
  body: TargetCreateBody,
): Promise<AdminScopeTarget> {
  const result = await callAdminBackendJson<AdminScopeTarget>(
    `/tenants/${enc(tenantId)}/targets`,
    {
      method: "POST",
      body: JSON.stringify(body),
    },
  );
  return assertOk(result);
}

export async function updateScopeTarget(
  tenantId: string,
  targetId: string,
  body: TargetPatchBody,
): Promise<AdminScopeTarget> {
  const result = await callAdminBackendJson<AdminScopeTarget>(
    `/tenants/${enc(tenantId)}/targets/${enc(targetId)}`,
    {
      method: "PATCH",
      body: JSON.stringify(body),
    },
  );
  return assertOk(result);
}

export async function deleteScopeTarget(
  tenantId: string,
  targetId: string,
): Promise<void> {
  const result = await callAdminBackendJson<void>(
    `/tenants/${enc(tenantId)}/targets/${enc(targetId)}`,
    { method: "DELETE" },
  );
  assertOk(result);
}

export async function previewScope(
  tenantId: string,
  body: PreviewScopeBody,
): Promise<PreviewScopeResult> {
  const payload = {
    probe: body.probe,
    rules: body.rules,
    ...(body.port != null ? { port: body.port } : {}),
    ...(body.dns_hostname != null && body.dns_hostname.trim() !== ""
      ? { dns_hostname: body.dns_hostname.trim() }
      : {}),
    ...(body.cidr != null && body.cidr.trim() !== ""
      ? { cidr: body.cidr.trim() }
      : {}),
  };
  const result = await callAdminBackendJson<PreviewScopeResult>(
    `/tenants/${enc(tenantId)}/preview-scope`,
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
  );
  return assertOk(result);
}
