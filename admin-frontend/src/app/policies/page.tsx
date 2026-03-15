"use client";

import { useCallback, useEffect, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi } from "@/lib/api";

type Policy = { id: string; tenant_id: string; policy_type: string; config: Record<string, unknown> | null; enabled: boolean; created_at: string };

export default function PoliciesPage() {
  const [data, setData] = useState<Policy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    adminApi.policies
      .list()
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => load(), [load]);

  if (error) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="mb-4 text-xl font-semibold">Policies</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-4 text-xl font-semibold">Policies</h1>
      {loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : (
        <DataTable<Policy>
          columns={[
            { key: "id", label: "ID", render: (r) => <code className="text-xs">{r.id.slice(0, 8)}...</code> },
            { key: "tenant_id", label: "Tenant", render: (r) => <code className="text-xs">{r.tenant_id.slice(0, 8)}...</code> },
            { key: "policy_type", label: "Type" },
            { key: "enabled", label: "Enabled", render: (r) => (r.enabled ? "Yes" : "No") },
            { key: "created_at", label: "Created", render: (r) => new Date(r.created_at).toLocaleString() },
          ]}
          data={data}
          emptyMessage="No policies"
        />
      )}
    </div>
  );
}
