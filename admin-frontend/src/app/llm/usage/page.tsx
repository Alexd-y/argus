"use client";

import { useEffect, useState } from "react";
import { adminApi } from "@/lib/api";

interface UsageSummary {
  total_calls: number;
  total_tokens: number;
  total_cost_usd: number;
  by_provider: Record<string, number>;
  by_model: Record<string, number>;
}

interface Invocation {
  id: string;
  alias: string;
  provider: string;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  estimated_cost_usd: number;
  latency_ms: number;
  status: string;
  created_at: string;
}

export default function LLMUsagePage() {
  const [summary, setSummary] = useState<UsageSummary | null>(null);
  const [invocations, setInvocations] = useState<Invocation[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      adminApi.llm.usage.summary(),
      adminApi.llm.usage.invocations({ limit: 50 }),
    ])
      .then(([s, invs]) => {
        setSummary(s);
        setInvocations(invs);
        setLoading(false);
      })
      .catch((e) => {
        setError(e instanceof Error ? e.message : "Failed");
        setLoading(false);
      });
  }, []);

  if (error) {
    return (
      <div>
        <h1 className="mb-4 text-xl font-semibold">LLM Usage &amp; Cost</h1>
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">{error}</div>
      </div>
    );
  }

  if (loading || !summary) {
    return (
      <div>
        <h1 className="mb-4 text-xl font-semibold">LLM Usage &amp; Cost</h1>
        <p className="text-neutral-500">Loading...</p>
      </div>
    );
  }

  const providerEntries = Object.entries(summary.by_provider);
  const modelEntries = Object.entries(summary.by_model);

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">LLM Usage &amp; Cost</h1>

      <div className="mb-6 grid grid-cols-3 gap-4">
        <div className="rounded border border-neutral-700 bg-neutral-900 p-4">
          <p className="text-xs text-neutral-400">Total Calls</p>
          <p className="text-2xl font-semibold">{summary.total_calls}</p>
        </div>
        <div className="rounded border border-neutral-700 bg-neutral-900 p-4">
          <p className="text-xs text-neutral-400">Total Tokens</p>
          <p className="text-2xl font-semibold">{summary.total_tokens.toLocaleString()}</p>
        </div>
        <div className="rounded border border-neutral-700 bg-neutral-900 p-4">
          <p className="text-xs text-neutral-400">Total Cost</p>
          <p className="text-2xl font-semibold">${summary.total_cost_usd.toFixed(4)}</p>
        </div>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-6">
        <div>
          <h2 className="mb-2 font-medium text-neutral-300">By Provider</h2>
          <div className="space-y-1">
            {providerEntries.map(([provider, tokens]) => (
              <div key={provider} className="flex justify-between rounded bg-neutral-900 px-3 py-1.5 text-sm">
                <span>{provider}</span>
                <span className="text-neutral-400">{tokens.toLocaleString()} tk</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <h2 className="mb-2 font-medium text-neutral-300">By Model</h2>
          <div className="space-y-1">
            {modelEntries.map(([model, tokens]) => (
              <div key={model} className="flex justify-between rounded bg-neutral-900 px-3 py-1.5 text-sm">
                <span className="font-mono">{model}</span>
                <span className="text-neutral-400">{tokens.toLocaleString()} tk</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {invocations.length > 0 && (
        <div>
          <h2 className="mb-2 font-medium text-neutral-300">Recent Invocations</h2>
          <div className="overflow-x-auto rounded border border-neutral-700">
            <table className="w-full text-xs">
              <thead className="border-b border-neutral-700 bg-neutral-900 text-left">
                <tr>
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Alias</th>
                  <th className="px-3 py-2">Provider</th>
                  <th className="px-3 py-2">Tokens</th>
                  <th className="px-3 py-2">Cost</th>
                  <th className="px-3 py-2">Latency</th>
                  <th className="px-3 py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {invocations.map((inv) => (
                  <tr key={inv.id} className="border-b border-neutral-800 hover:bg-neutral-900/50">
                    <td className="px-3 py-1.5">{new Date(inv.created_at).toLocaleTimeString()}</td>
                    <td className="px-3 py-1.5">{inv.alias}</td>
                    <td className="px-3 py-1.5">{inv.provider}</td>
                    <td className="px-3 py-1.5">{(inv.prompt_tokens + inv.completion_tokens).toLocaleString()}</td>
                    <td className="px-3 py-1.5">${inv.estimated_cost_usd.toFixed(6)}</td>
                    <td className="px-3 py-1.5">{inv.latency_ms}ms</td>
                    <td className="px-3 py-1.5">
                      <span className={inv.status === "completed" ? "text-green-400" : "text-red-400"}>
                        {inv.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
