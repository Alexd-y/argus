"use client";

import { useCallback, useEffect, useState } from "react";
import { cairnApi, type CairnWorker } from "@/lib/cairnApi";

const WORKER_TYPES = ["wrb", "claudecode", "codex", "pi", "mock"];
const ALL_TASK_TYPES = ["bootstrap", "reason", "explore"];

export default function CairnWorkersPage() {
  const [workers, setWorkers] = useState<CairnWorker[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ name: "", type: "wrb", task_types: ["reason", "explore"] });

  const load = useCallback(() => {
    setLoading(true);
    cairnApi
      .listWorkers()
      .then(setWorkers)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => load(), [load]);

  const create = (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim() || form.task_types.length === 0) return;
    cairnApi
      .createWorker({ name: form.name.trim(), type: form.type, task_types: form.task_types })
      .then(() => {
        setForm({ name: "", type: "wrb", task_types: ["reason", "explore"] });
        load();
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed"));
  };

  const toggle = (w: CairnWorker) => {
    cairnApi.updateWorker(w.id, { enabled: !w.enabled }).then(load).catch((e) => setError(e instanceof Error ? e.message : "Failed"));
  };

  const remove = (w: CairnWorker) => {
    cairnApi.deleteWorker(w.id).then(load).catch((e) => setError(e instanceof Error ? e.message : "Failed"));
  };

  const toggleTaskType = (tt: string) => {
    setForm((f) => ({
      ...f,
      task_types: f.task_types.includes(tt) ? f.task_types.filter((x) => x !== tt) : [...f.task_types, tt],
    }));
  };

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-4 text-xl font-semibold">Cairn — workers</h1>
      {error && (
        <div className="mb-4 rounded border border-red-900/50 bg-red-950/30 p-3 text-sm text-red-400">{error}</div>
      )}

      <form onSubmit={create} className="mb-6 flex flex-wrap items-center gap-2 rounded border border-neutral-800 bg-neutral-950/50 p-4">
        <input
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          placeholder="Worker name"
          className="rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-white placeholder:text-neutral-500"
        />
        <select
          value={form.type}
          onChange={(e) => setForm({ ...form, type: e.target.value })}
          className="rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-white"
        >
          {WORKER_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <div className="flex gap-2 text-sm text-neutral-300">
          {ALL_TASK_TYPES.map((tt) => (
            <label key={tt} className="flex items-center gap-1">
              <input type="checkbox" checked={form.task_types.includes(tt)} onChange={() => toggleTaskType(tt)} />
              {tt}
            </label>
          ))}
        </div>
        <button type="submit" className="rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500">
          Add worker
        </button>
      </form>

      {loading ? (
        <p className="text-neutral-500">Loading...</p>
      ) : workers.length === 0 ? (
        <p className="text-neutral-500">No workers configured.</p>
      ) : (
        <div className="overflow-x-auto rounded border border-neutral-800">
          <table className="w-full text-sm">
            <thead className="bg-neutral-900/60 text-left text-neutral-400">
              <tr>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Task types</th>
                <th className="px-3 py-2">Priority</th>
                <th className="px-3 py-2">Max</th>
                <th className="px-3 py-2">Enabled</th>
                <th className="px-3 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {workers.map((w) => (
                <tr key={w.id} className="border-t border-neutral-800">
                  <td className="px-3 py-2">{w.name}</td>
                  <td className="px-3 py-2 font-mono text-xs">{w.type}</td>
                  <td className="px-3 py-2 text-neutral-400">{w.task_types.join(", ")}</td>
                  <td className="px-3 py-2">{w.priority}</td>
                  <td className="px-3 py-2">{w.max_running}</td>
                  <td className="px-3 py-2">{w.enabled ? "✓" : "—"}</td>
                  <td className="px-3 py-2">
                    <button onClick={() => toggle(w)} className="mr-2 text-indigo-400 hover:underline">
                      {w.enabled ? "Disable" : "Enable"}
                    </button>
                    <button onClick={() => remove(w)} className="text-red-400 hover:underline">
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
