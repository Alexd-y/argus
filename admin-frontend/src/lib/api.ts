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
};
