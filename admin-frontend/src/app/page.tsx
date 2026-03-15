"use client";

import { useEffect, useState } from "react";
import { adminApi } from "@/lib/api";

export default function HealthPage() {
  const [data, setData] = useState<{
    database: boolean;
    redis: boolean;
    storage: boolean;
    status: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    adminApi.health
      .dashboard()
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"));
  }, []);

  if (error) {
    return (
      <div className="mx-auto max-w-2xl">
        <h1 className="mb-4 text-xl font-semibold">Health Dashboard</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="mx-auto max-w-2xl">
        <h1 className="mb-4 text-xl font-semibold">Health Dashboard</h1>
        <p className="text-neutral-500">Loading...</p>
      </div>
    );
  }

  const items = [
    { label: "Database", ok: data.database },
    { label: "Redis", ok: data.redis },
    { label: "Storage", ok: data.storage },
  ];

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="mb-4 text-xl font-semibold">Health Dashboard</h1>
      <div className="mb-4 flex items-center gap-2">
        <span
          className={`inline-block h-3 w-3 rounded-full ${
            data.status === "ok" ? "bg-green-500" : "bg-amber-500"
          }`}
        />
        <span className="text-neutral-400">Status: {data.status}</span>
      </div>
      <div className="grid gap-3">
        {items.map(({ label, ok }) => (
          <div
            key={label}
            className="flex items-center justify-between rounded border border-neutral-700 bg-neutral-900 px-4 py-3"
          >
            <span>{label}</span>
            <span className={ok ? "text-green-400" : "text-red-400"}>
              {ok ? "OK" : "Down"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
