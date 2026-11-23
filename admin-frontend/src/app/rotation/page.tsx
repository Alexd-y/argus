"use client";

import { useCallback, useState } from "react";
import { adminApi, type RotationState } from "@/lib/api";

const splitCsv = (s: string): string[] =>
  s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

export default function RotationPage() {
  const [tenantId, setTenantId] = useState("");
  const [role, setRole] = useState("report");
  const [scanId, setScanId] = useState("");
  const [profiles, setProfiles] = useState("");

  const [state, setState] = useState<RotationState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async (fn: () => Promise<RotationState>) => {
    setBusy(true);
    setError(null);
    try {
      setState(await fn());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }, []);

  const load = () =>
    run(() =>
      adminApi.rotation.get({
        tenant_id: tenantId,
        role,
        scan_id: scanId || undefined,
      })
    );

  const save = () =>
    run(() =>
      adminApi.rotation.set({
        tenant_id: tenantId,
        role,
        profile_ids: splitCsv(profiles),
        scan_id: scanId || undefined,
      })
    );

  const inputCls =
    "w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-1.5 text-sm text-neutral-100 placeholder:text-neutral-600";
  const btnCls =
    "rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-500 disabled:opacity-50";

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <h1 className="text-xl font-semibold">LLM Rotation</h1>
      <p className="text-sm text-neutral-500">
        Rotation applies only to safe non-sensitive roles; WRB-001 keeps sensitive
        pentest analysis WRB-first.
      </p>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="sm:col-span-3">
          <label className="block text-xs text-neutral-400">Tenant ID (UUID)</label>
          <input
            className={inputCls}
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
        <div>
          <label className="block text-xs text-neutral-400">Role</label>
          <input className={inputCls} value={role} onChange={(e) => setRole(e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <label className="block text-xs text-neutral-400">Scan ID (optional)</label>
          <input
            className={inputCls}
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            placeholder="leave empty for tenant-wide"
          />
        </div>
      </div>

      <div className="flex gap-2">
        <button className={btnCls} onClick={load} disabled={busy || !tenantId}>
          Load current
        </button>
      </div>

      <div className="rounded border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
        <h2 className="text-sm font-medium text-neutral-300">Set rotation chain</h2>
        <input
          className={inputCls}
          value={profiles}
          onChange={(e) => setProfiles(e.target.value)}
          placeholder="ordered profile_ids (comma-separated, e.g. argus-nvidia-hosted,deepseek)"
        />
        <button className={btnCls} onClick={save} disabled={busy || !tenantId}>
          Save chain
        </button>
      </div>

      {error && (
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      )}

      {state && (
        <div className="rounded border border-neutral-700 bg-neutral-900 p-4 text-sm space-y-2">
          <div>
            <span className="text-neutral-500">role:</span>{" "}
            <code className="text-neutral-200">{state.role}</code>
          </div>
          <div>
            <span className="text-neutral-500">scan_id:</span>{" "}
            <code className="text-neutral-200">{state.scan_id ?? "—"}</code>
          </div>
          <div>
            <span className="text-neutral-500">profile_ids:</span>{" "}
            <code className="text-neutral-200">{state.profile_ids.join(" → ") || "—"}</code>
          </div>
          <div>
            <span className="text-neutral-500">cursor:</span>{" "}
            <code className="text-neutral-200">{state.cursor}</code>
          </div>
          <div>
            <span className="text-neutral-500">excluded:</span>{" "}
            <code className="text-neutral-200">{state.excluded.join(", ") || "—"}</code>
          </div>
        </div>
      )}
    </div>
  );
}
