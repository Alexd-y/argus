"use client";

import { useEffect, useState } from "react";
import { adminApi } from "@/lib/api";

interface AliasRecord {
  id: string;
  alias: string;
  provider_key: string;
  model: string;
  role: string;
  cloud_allowed: boolean;
  enabled: boolean;
}

export default function LLMAliasesPage() {
  const [aliases, setAliases] = useState<AliasRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    adminApi.llm.aliases
      .list()
      .then((data) => { setAliases(data); setLoading(false); })
      .catch((e) => { setError(e instanceof Error ? e.message : "Failed"); setLoading(false); });
  }, []);

  if (error) {
    return (
      <div>
        <h1 className="mb-4 text-xl font-semibold">LLM Model Aliases</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">{error}</div>
      </div>
    );
  }

  if (loading) {
    return (
      <div>
        <h1 className="mb-4 text-xl font-semibold">LLM Model Aliases</h1>
        <p className="text-neutral-500">Loading...</p>
      </div>
    );
  }

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">LLM Model Aliases</h1>
      <p className="mb-4 text-sm text-neutral-400">
        These aliases map logical names to concrete provider/model configurations.
      </p>
      <div className="overflow-x-auto rounded border border-neutral-700">
        <table className="w-full text-sm">
          <thead className="border-b border-neutral-700 bg-neutral-900 text-left">
            <tr>
              <th className="px-4 py-2">Alias</th>
              <th className="px-4 py-2">Role</th>
              <th className="px-4 py-2">Provider</th>
              <th className="px-4 py-2">Model</th>
              <th className="px-4 py-2">Cloud</th>
              <th className="px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {aliases.map((a) => (
              <tr key={a.id} className="border-b border-neutral-800 hover:bg-neutral-900/50">
                <td className="px-4 py-2 font-mono">{a.alias}</td>
                <td className="px-4 py-2">
                  <span className="rounded bg-neutral-800 px-2 py-0.5 text-xs">{a.role}</span>
                </td>
                <td className="px-4 py-2">{a.provider_key}</td>
                <td className="px-4 py-2 text-neutral-400">{a.model}</td>
                <td className="px-4 py-2">{a.cloud_allowed ? "Yes" : "Local"}</td>
                <td className="px-4 py-2">
                  <span
                    className={`inline-block h-2 w-2 rounded-full ${
                      a.enabled ? "bg-green-500" : "bg-red-500"
                    }`}
                  />{" "}
                  {a.enabled ? "Enabled" : "Disabled"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
