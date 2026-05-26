"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import type { WrbDashboardData, WrbTestPromptResult } from "./types";

export type { WrbDashboardData, WrbTestPromptResult };

const WRB_FALLBACK_DASHBOARD: WrbDashboardData = {
  status: "unconfigured",
  model: "",
  provider: "whiterabbitneo",
  error: "",
  models_count: 0,
  base_url: "",
  timeout_seconds: 600,
  gpu_mode: "",
  concurrency_limit: 3,
  default_temperature: 0.3,
  default_max_tokens: 4096,
  max_prompt_bytes: 8192,
  api_key_configured: false,
};

export async function getWrbDashboard(): Promise<WrbDashboardData> {
  const result = await callAdminBackendJson<WrbDashboardData>(
    "/llm/wrb/dashboard",
    { method: "GET" },
  );

  if (!result.ok) {
    if (result.status === 503) return { ...WRB_FALLBACK_DASHBOARD };
    throw new Error(`Failed to fetch WRB dashboard: ${result.status}`);
  }

  return result.data;
}

export async function wrbTestPrompt(
  prompt: string,
  systemPrompt?: string,
): Promise<WrbTestPromptResult> {
  const result = await callAdminBackendJson<WrbTestPromptResult>(
    "/llm/wrb/test-prompt",
    {
      method: "POST",
      body: JSON.stringify({
        prompt,
        system_prompt: systemPrompt || null,
      }),
    },
  );

  if (!result.ok) {
    throw new Error(`WRB test prompt failed: ${result.status}`);
  }

  return result.data;
}