"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";

export type LlmRuntimeSummary = {
  execution_uses_global_env: boolean;
  global_env_providers: Record<string, boolean>;
};

export type AdminLlmProviderRow = {
  id: string;
  tenant_id: string;
  provider_key: string;
  enabled: boolean;
  config: Record<string, unknown> | null;
  api_key_last4: string | null;
  api_key_set: boolean;
  model_fallback_chain: string[] | null;
  created_at: string;
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

export async function getLlmRuntimeSummary(): Promise<LlmRuntimeSummary> {
  const result = await callAdminBackendJson<LlmRuntimeSummary>("/llm/runtime-summary", {
    method: "GET",
  });
  return assertOk(result);
}

export async function listLlmProvidersForTenant(
  tenantId: string,
): Promise<AdminLlmProviderRow[]> {
  const sp = new URLSearchParams();
  sp.set("tenant_id", tenantId);
  const result = await callAdminBackendJson<AdminLlmProviderRow[]>(
    `/providers?${sp.toString()}`,
    { method: "GET" },
  );
  return assertOk(result);
}

export async function createLlmProviderRow(params: {
  tenantId: string;
  providerKey: string;
}): Promise<AdminLlmProviderRow> {
  const result = await callAdminBackendJson<AdminLlmProviderRow>("/providers", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: params.tenantId,
      provider_key: params.providerKey,
      enabled: true,
    }),
  });
  return assertOk(result);
}

export async function patchLlmProvider(params: {
  providerId: string;
  enabled?: boolean;
  apiKey?: string;
  modelFallbackChain?: string[] | null;
}): Promise<AdminLlmProviderRow> {
  const body: Record<string, unknown> = {};
  if (params.enabled !== undefined) body.enabled = params.enabled;
  if (params.apiKey !== undefined) body.api_key = params.apiKey;
  if (params.modelFallbackChain !== undefined) {
    body.model_fallback_chain = params.modelFallbackChain;
  }
  const result = await callAdminBackendJson<AdminLlmProviderRow>(
    `/providers/${enc(params.providerId)}`,
    {
      method: "PATCH",
      body: JSON.stringify(body),
    },
  );
  return assertOk(result);
}
