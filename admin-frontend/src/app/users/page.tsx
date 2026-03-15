"use client";

import { useCallback, useEffect, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi } from "@/lib/api";

type User = { id: string; tenant_id: string; email: string; is_active: boolean; created_at: string };

export default function UsersPage() {
  const [data, setData] = useState<User[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    adminApi.users
      .list()
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => load(), [load]);

  if (error) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="mb-4 text-xl font-semibold">Users</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-4 text-xl font-semibold">Users</h1>
      {loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : (
        <DataTable<User>
          columns={[
            { key: "id", label: "ID", render: (r) => <code className="text-xs">{r.id.slice(0, 8)}...</code> },
            { key: "tenant_id", label: "Tenant", render: (r) => <code className="text-xs">{r.tenant_id.slice(0, 8)}...</code> },
            { key: "email", label: "Email" },
            { key: "is_active", label: "Active", render: (r) => (r.is_active ? "Yes" : "No") },
            { key: "created_at", label: "Created", render: (r) => new Date(r.created_at).toLocaleString() },
          ]}
          data={data}
          emptyMessage="No users"
        />
      )}
    </div>
  );
}
