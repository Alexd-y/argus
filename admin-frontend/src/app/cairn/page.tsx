"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { cairnApi, type CairnProjectSummary } from "@/lib/cairnApi";

const STATUS_COLORS: Record<string, string> = {
  active: "text-emerald-400",
  stopped: "text-amber-400",
  completed: "text-indigo-400",
};

export default function CairnProjectsPage() {
  const [data, setData] = useState<CairnProjectSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ title: "", origin: "", goal: "" });

  const load = useCallback(() => {
    setLoading(true);
    cairnApi
      .listProjects(statusFilter || undefined)
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, [statusFilter]);

  useEffect(() => load(), [load]);

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.title.trim() || !form.origin.trim() || !form.goal.trim()) return;
    setCreating(true);
    cairnApi
      .createProject({ title: form.title.trim(), origin: form.origin.trim(), goal: form.goal.trim() })
      .then(() => {
        setForm({ title: "", origin: "", goal: "" });
        load();
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setCreating(false));
  };

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Cairn — search projects</h1>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded border border-neutral-600 bg-neutral-900 px-3 py-1.5 text-sm text-white"
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="stopped">Stopped</option>
          <option value="completed">Completed</option>
        </select>
      </div>

      {error && (
        <div className="mb-4 rounded border border-red-900/50 bg-red-950/30 p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <form onSubmit={handleCreate} className="mb-6 grid grid-cols-1 gap-2 rounded border border-neutral-800 bg-neutral-950/50 p-4 md:grid-cols-4">
        <input
          value={form.title}
          onChange={(e) => setForm({ ...form, title: e.target.value })}
          placeholder="Title"
          className="rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-white placeholder:text-neutral-500"
        />
        <input
          value={form.origin}
          onChange={(e) => setForm({ ...form, origin: e.target.value })}
          placeholder="Origin (starting point)"
          className="rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-white placeholder:text-neutral-500"
        />
        <input
          value={form.goal}
          onChange={(e) => setForm({ ...form, goal: e.target.value })}
          placeholder="Goal (objective)"
          className="rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-white placeholder:text-neutral-500"
        />
        <button
          type="submit"
          disabled={creating}
          className="rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500 disabled:opacity-50"
        >
          {creating ? "Creating..." : "Create project"}
        </button>
      </form>

      {loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : data.length === 0 ? (
        <p className="text-neutral-500">No Cairn projects.</p>
      ) : (
        <div className="overflow-x-auto rounded border border-neutral-800">
          <table className="w-full text-sm">
            <thead className="bg-neutral-900/60 text-left text-neutral-400">
              <tr>
                <th className="px-3 py-2">Ref</th>
                <th className="px-3 py-2">Title</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Facts</th>
                <th className="px-3 py-2">Intents</th>
                <th className="px-3 py-2">Working</th>
                <th className="px-3 py-2">Hints</th>
                <th className="px-3 py-2">Reason worker</th>
              </tr>
            </thead>
            <tbody>
              {data.map((p) => (
                <tr key={p.id} className="border-t border-neutral-800 hover:bg-neutral-900/40">
                  <td className="px-3 py-2 font-mono text-xs">
                    <Link href={`/cairn/${p.id}`} className="text-indigo-400 hover:underline">
                      {p.ref}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <Link href={`/cairn/${p.id}`} className="hover:underline">
                      {p.title}
                    </Link>
                  </td>
                  <td className={`px-3 py-2 font-medium ${STATUS_COLORS[p.status] ?? ""}`}>{p.status}</td>
                  <td className="px-3 py-2">{p.fact_count}</td>
                  <td className="px-3 py-2">{p.intent_count}</td>
                  <td className="px-3 py-2">{p.working_intent_count}</td>
                  <td className="px-3 py-2">{p.hint_count}</td>
                  <td className="px-3 py-2 text-neutral-400">{p.reason?.worker ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
