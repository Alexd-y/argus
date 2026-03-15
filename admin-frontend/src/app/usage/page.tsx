"use client";

import { useCallback, useEffect, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi } from "@/lib/api";

type Usage = { id: string; tenant_id: string; metric_type: string; value: number; recorded_at: string };

export default function UsagePage() {
  const [data, setData] = useState<Usage[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    adminApi.usage
      .list()
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => load(), [load]);

  if (error) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="mb-4 text-xl font-semibold">Usage Metering</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-4 text-xl font-semibold">Usage Metering</h1>
      {loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : (
        <DataTable<Usage>
          columns={[
            { key: "id", label: "ID", render: (r) => <code className="text-xs">{r.id.slice(0, 8)}...</code> },
            { key: "tenant_id", label: "Tenant", render: (r) => <code className="text-xs">{r.tenant_id.slice(0, 8)}...</code> },
            { key: "metric_type", label: "Metric" },
            { key: "value", label: "Value" },
            { key: "recorded_at", label: "Recorded", render: (r) => new Date(r.recorded_at).toLocaleString() },
          ]}
          data={data}
          emptyMessage="No usage records"
        />
      )}
    </div>
  );
}
