"use client";

import { useCallback, useEffect, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi } from "@/lib/api";

type Tenant = { id: string; name: string; created_at: string; updated_at: string };

export default function TenantsPage() {
  const [data, setData] = useState<Tenant[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    adminApi.tenants
      .list()
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => load(), [load]);

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    adminApi.tenants
      .create({ name: name.trim() })
      .then(() => {
        setName("");
        load();
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setCreating(false));
  };

  if (error) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="mb-4 text-xl font-semibold">Tenants</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-4 text-xl font-semibold">Tenants</h1>
      <form onSubmit={handleCreate} className="mb-4 flex gap-2">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Tenant name"
          className="rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-white placeholder:text-neutral-500 focus:border-indigo-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={creating || !name.trim()}
          className="rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500 disabled:opacity-50"
        >
          {creating ? "Creating..." : "Create"}
        </button>
      </form>
      {loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : (
        <DataTable<Tenant>
          columns={[
            { key: "id", label: "ID", render: (r) => <code className="text-xs">{r.id.slice(0, 8)}...</code> },
            { key: "name", label: "Name" },
            { key: "created_at", label: "Created", render: (r) => new Date(r.created_at).toLocaleString() },
          ]}
          data={data}
          emptyMessage="No tenants"
        />
      )}
    </div>
  );
}
