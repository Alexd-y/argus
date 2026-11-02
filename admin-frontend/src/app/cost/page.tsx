"use client";

import { useCallback, useEffect, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi } from "@/lib/api";

type CostDashboard = Awaited<ReturnType<typeof adminApi.llm.costDashboard>>;
type PriceRow = CostDashboard["price_table"][number];
type RoutingRow = { phase: string; mode: string; primary_alias: string; fallback: boolean };

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-neutral-800 bg-neutral-900/50 p-4">
      <div className="text-xs uppercase tracking-wide text-neutral-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-white">{value}</div>
    </div>
  );
}

const usd = (n: number) => `$${(n ?? 0).toLocaleString(undefined, { maximumFractionDigits: 4 })}`;
const num = (n: number) => (n ?? 0).toLocaleString();

export default function CostDashboardPage() {
  const [data, setData] = useState<CostDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tenantId, setTenantId] = useState("");
  const [scanId, setScanId] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    adminApi.llm
      .costDashboard({ tenant_id: tenantId.trim() || undefined, scan_id: scanId.trim() || undefined })
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, [tenantId, scanId]);

  useEffect(() => load(), [load]);

  const routingRows: RoutingRow[] = data
    ? Object.entries(data.phase_routing).map(([phase, r]) => ({ phase, ...r }))
    : [];

  return (
    <div className="mx-auto max-w-5xl">
      <h1 className="mb-4 text-xl font-semibold">LLM Cost Dashboard</h1>

      <div className="mb-4 flex flex-wrap items-end gap-2">
        <label className="flex flex-col text-xs text-neutral-500">
          Tenant ID (optional)
          <input
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder="all tenants"
            className="mt-1 rounded border border-neutral-800 bg-neutral-900 px-2 py-1 text-sm text-white"
          />
        </label>
        <label className="flex flex-col text-xs text-neutral-500">
          Scan ID (optional)
          <input
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            placeholder="all scans"
            className="mt-1 rounded border border-neutral-800 bg-neutral-900 px-2 py-1 text-sm text-white"
          />
        </label>
        <button
          onClick={load}
          className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500"
        >
          Refresh
        </button>
      </div>

      {error ? (
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">{error}</div>
      ) : loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : data ? (
        <div className="space-y-8">
          <section className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Stat label="Total LLM calls" value={num(data.usage.total_calls)} />
            <Stat label="Total tokens" value={num(data.usage.total_tokens)} />
            <Stat label="Total cost" value={usd(data.usage.total_cost_usd)} />
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold text-neutral-300">
              Price table — model &amp; $/role (cloud vs local)
            </h2>
            <DataTable<PriceRow>
              columns={[
                { key: "role", label: "Role" },
                { key: "alias", label: "Alias", render: (r) => <code className="text-xs">{r.alias}</code> },
                { key: "model", label: "Model", render: (r) => <code className="text-xs">{r.model || "-"}</code> },
                {
                  key: "cloud",
                  label: "Location",
                  render: (r) =>
                    r.cloud ? (
                      <span className="text-amber-400">cloud</span>
                    ) : (
                      <span className="text-emerald-400">local</span>
                    ),
                },
                { key: "price_input_per_million_usd", label: "In $/M", render: (r) => usd(r.price_input_per_million_usd) },
                { key: "price_output_per_million_usd", label: "Out $/M", render: (r) => usd(r.price_output_per_million_usd) },
              ]}
              data={data.price_table}
              emptyMessage="No price table (alias registry unavailable)"
            />
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold text-neutral-300">
              Effective phase routing — model per phase
            </h2>
            <DataTable<RoutingRow>
              columns={[
                { key: "phase", label: "Phase" },
                { key: "mode", label: "Mode" },
                { key: "primary_alias", label: "Primary alias", render: (r) => <code className="text-xs">{r.primary_alias}</code> },
                { key: "fallback", label: "Fallback", render: (r) => (r.fallback ? "Yes" : "No") },
              ]}
              data={routingRows}
              emptyMessage="Phase routing not enabled"
            />
          </section>
        </div>
      ) : null}
    </div>
  );
}
