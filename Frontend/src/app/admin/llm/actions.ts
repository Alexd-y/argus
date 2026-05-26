"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import type { LlmRuntimeSummary, AdminLlmProviderRow } from "./types";

export type { LlmRuntimeSummary, AdminLlmProviderRow };

const FALLBACK_RUNTIME: LlmRuntimeSummary = {
  execution_uses_global_env: false,
  global_env_providers: {},
};

function enc(s: string): string {
  return encodeURIComponent(s);
}

export async function getLlmRuntimeSummary(): Promise<LlmRuntimeSummary | null> {
  const result = await callAdminBackendJson<LlmRuntimeSummary>("/llm/runtime-summary", {
    method: "GET",
  });
  if (!result.ok) {
    if (result.status === 503) return { ...FALLBACK_RUNTIME };
    return null;
  }
  return result.data;
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
  if (!result.ok) {
    throw new Error(result.error);
  }
  return result.data;
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
  if (!result.ok) {
    throw new Error(result.error);
  }
  return result.data;
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
  if (!result.ok) {
    throw new Error(result.error);
  }
  return result.data;
}