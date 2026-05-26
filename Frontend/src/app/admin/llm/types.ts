export type WrbDashboardData = {
  status: string;
  model: string;
  provider: string;
  error: string;
  models_count: number;
  base_url: string;
  timeout_seconds: number;
  gpu_mode: string;
  concurrency_limit: number;
  default_temperature: number;
  default_max_tokens: number;
  max_prompt_bytes: number;
  api_key_configured: boolean;
};

export type WrbTestPromptResult = {
  response: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  elapsed_ms: number;
};

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