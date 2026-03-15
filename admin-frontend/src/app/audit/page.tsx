"use client";

import { useCallback, useEffect, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi } from "@/lib/api";

type AuditLog = { id: string; tenant_id: string; user_id: string | null; action: string; resource_type: string | null; resource_id: string | null; details: Record<string, unknown> | null; created_at: string };

export default function AuditPage() {
  const [data, setData] = useState<AuditLog[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    adminApi.auditLogs
      .list()
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => load(), [load]);

  if (error) {
    return (
      <div className="mx-auto max-w-5xl">
        <h1 className="mb-4 text-xl font-semibold">Audit Logs</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl">
      <h1 className="mb-4 text-xl font-semibold">Audit Logs</h1>
      {loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : (
        <DataTable<AuditLog>
          columns={[
            { key: "created_at", label: "Time", render: (r) => new Date(r.created_at).toLocaleString() },
            { key: "tenant_id", label: "Tenant", render: (r) => <code className="text-xs">{r.tenant_id.slice(0, 8)}...</code> },
            { key: "user_id", label: "User", render: (r) => r.user_id ? <code className="text-xs">{r.user_id.slice(0, 8)}...</code> : "-" },
            { key: "action", label: "Action" },
            { key: "resource_type", label: "Resource", render: (r) => r.resource_type ?? "-" },
            { key: "resource_id", label: "Resource ID", render: (r) => r.resource_id ? <code className="text-xs">{r.resource_id.slice(0, 8)}...</code> : "-" },
          ]}
          data={data}
          emptyMessage="No audit logs"
        />
      )}
    </div>
  );
}
