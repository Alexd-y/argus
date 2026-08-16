/** Admin API client — calls /api/v1/admin/* endpoints. */

const getBaseUrl = () =>
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const getAdminKey = () =>
  typeof window !== "undefined"
    ? (localStorage.getItem("admin_key") ?? process.env.NEXT_PUBLIC_ADMIN_KEY ?? "")
    : process.env.NEXT_PUBLIC_ADMIN_KEY ?? "";

async function fetchAdmin<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${getBaseUrl()}/api/v1/admin${path}`;
  const adminKey = getAdminKey();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (adminKey) {
    headers["X-Admin-Key"] = adminKey;
  }

  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error((err as { detail?: string }).detail ?? "Request failed");
  }
  return res.json() as Promise<T>;
}

export const adminApi = {
  tenants: {
    list: (params?: { limit?: number; offset?: number }) => {
      const q = new URLSearchParams();
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      return fetchAdmin<Array<{ id: string; name: string; created_at: string; updated_at: string }>>(
        `/tenants?${q}`
      );
    },
    create: (body: { name: string }) =>
      fetchAdmin<{ id: string; name: string; created_at: string; updated_at: string }>(
        "/tenants",
        { method: "POST", body: JSON.stringify(body) }
      ),
  },
  users: {
    list: (params?: { tenant_id?: string; limit?: number; offset?: number }) => {
      const q = new URLSearchParams();
      if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      return fetchAdmin<Array<{ id: string; tenant_id: string; email: string; is_active: boolean; created_at: string }>>(
        `/users?${q}`
      );
    },
  },
  subscriptions: {
    list: (params?: { tenant_id?: string; limit?: number; offset?: number }) => {
      const q = new URLSearchParams();
      if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      return fetchAdmin<Array<{ id: string; tenant_id: string; plan: string; status: string; valid_until: string | null; created_at: string }>>(
        `/subscriptions?${q}`
      );
    },
  },
  providers: {
    list: (params?: { tenant_id?: string; limit?: number; offset?: number }) => {
      const q = new URLSearchParams();
      if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      return fetchAdmin<Array<{ id: string; tenant_id: string; provider_key: string; enabled: boolean; config: Record<string, unknown> | null; created_at: string }>>(
        `/providers?${q}`
      );
    },
    update: (id: string, body: { enabled?: boolean; config?: Record<string, unknown> }) =>
      fetchAdmin<{ id: string; tenant_id: string; provider_key: string; enabled: boolean; config: Record<string, unknown> | null; created_at: string }>(
        `/providers/${id}`,
        { method: "PATCH", body: JSON.stringify(body) }
      ),
  },
  policies: {
    list: (params?: { tenant_id?: string; limit?: number; offset?: number }) => {
      const q = new URLSearchParams();
      if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      return fetchAdmin<Array<{ id: string; tenant_id: string; policy_type: string; config: Record<string, unknown> | null; enabled: boolean; created_at: string }>>(
        `/policies?${q}`
      );
    },
  },
  auditLogs: {
    list: (params?: { tenant_id?: string; limit?: number; offset?: number }) => {
      const q = new URLSearchParams();
      if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      return fetchAdmin<Array<{ id: string; tenant_id: string; user_id: string | null; action: string; resource_type: string | null; resource_id: string | null; details: Record<string, unknown> | null; created_at: string }>>(
        `/audit-logs?${q}`
      );
    },
  },
  usage: {
    list: (params?: { tenant_id?: string; metric_type?: string; limit?: number; offset?: number }) => {
      const q = new URLSearchParams();
      if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
      if (params?.metric_type) q.set("metric_type", params.metric_type);
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      return fetchAdmin<Array<{ id: string; tenant_id: string; metric_type: string; value: number; recorded_at: string }>>(
        `/usage?${q}`
      );
    },
  },
  health: {
    dashboard: () =>
      fetchAdmin<{ database: boolean; redis: boolean; storage: boolean; status: string }>(
        "/health/dashboard"
      ),
  },
  emergency: {
    status: () =>
      fetchAdmin<{
        global_state: { active: boolean; reason?: string | null };
        tenant_throttles: unknown[];
        queried_at: string;
      }>("/system/emergency/status"),
    stopAll: (body: { reason: string; confirmation_phrase: string }) =>
      fetchAdmin<{
        status: "stopped";
        cancelled_count: number;
        skipped_terminal_count: number;
        tenants_affected: number;
        activated_at: string;
        audit_id: string;
      }>("/system/emergency/stop_all", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  },
  llm: {
    aliases: {
      list: (params?: { tenant_id?: string }) => {
        const q = new URLSearchParams();
        if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
        return fetchAdmin<Array<{ id: string; alias: string; provider_key: string; model: string; role: string; cloud_allowed: boolean; enabled: boolean }>>(
          `/gateway/providers?${q}`
        );
      },
    },
    usage: {
      summary: (params?: { tenant_id?: string; scan_id?: string }) => {
        const q = new URLSearchParams();
        if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
        if (params?.scan_id) q.set("scan_id", params.scan_id);
        return fetchAdmin<{ total_calls: number; total_tokens: number; total_cost_usd: number; by_provider: Record<string, number>; by_model: Record<string, number> }>(
          `/gateway/usage?${q}`
        );
      },
      invocations: (params?: { tenant_id?: string; scan_id?: string; limit?: number }) => {
        const q = new URLSearchParams();
        if (params?.tenant_id) q.set("tenant_id", params.tenant_id);
        if (params?.scan_id) q.set("scan_id", params.scan_id);
        if (params?.limit) q.set("limit", String(params.limit ?? 50));
        return fetchAdmin<Array<{ id: string; alias: string; provider: string; model: string; prompt_tokens: number; completion_tokens: number; estimated_cost_usd: number; latency_ms: number; status: string; created_at: string }>>(
          `/gateway/invocations?${q}`
        );
      },
      perTenant: (tenant_id: string) => {
        return fetchAdmin<{ tenant_id: string; total_calls: number; total_tokens: number; total_cost_usd: number; providers: Record<string, { calls: number; tokens: number; cost_usd: number }> }>(
          `/gateway/usage?tenant_id=${tenant_id}`
        );
      },
    },
    health: {
      wrb: () =>
        fetch("/api/v1/llm/whiterabbitneo/health").then(r => r.json()),
      all: () =>
        fetch("/api/v1/llm/health/all").then(r => r.json()),
    },
  },
};
