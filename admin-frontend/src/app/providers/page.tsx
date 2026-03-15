"use client";

import { useCallback, useEffect, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi } from "@/lib/api";

type Provider = { id: string; tenant_id: string; provider_key: string; enabled: boolean; config: Record<string, unknown> | null; created_at: string };

export default function ProvidersPage() {
  const [data, setData] = useState<Provider[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    adminApi.providers
      .list()
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => load(), [load]);

  const toggleEnabled = (p: Provider) => {
    adminApi.providers
      .update(p.id, { enabled: !p.enabled })
      .then(load)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"));
  };

  if (error) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="mb-4 text-xl font-semibold">Providers</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-4 text-xl font-semibold">Providers</h1>
      {loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : (
        <DataTable<Provider>
          columns={[
            { key: "id", label: "ID", render: (r) => <code className="text-xs">{r.id.slice(0, 8)}...</code> },
            { key: "tenant_id", label: "Tenant", render: (r) => <code className="text-xs">{r.tenant_id.slice(0, 8)}...</code> },
            { key: "provider_key", label: "Provider" },
            {
              key: "enabled",
              label: "Enabled",
              render: (r) => (
                <button
                  type="button"
                  onClick={() => toggleEnabled(r)}
                  className={`rounded px-2 py-1 text-xs ${r.enabled ? "bg-green-900/50 text-green-400" : "bg-neutral-700 text-neutral-400"}`}
                >
                  {r.enabled ? "Yes" : "No"}
                </button>
              ),
            },
            { key: "created_at", label: "Created", render: (r) => new Date(r.created_at).toLocaleString() },
          ]}
          data={data}
          emptyMessage="No provider configs"
        />
      )}
    </div>
  );
}
