"use client";

import { useCallback, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi, type Approval } from "@/lib/api";

const fmt = (ts: string | null): string => (ts ? new Date(ts).toLocaleString() : "—");

export default function ApprovalsPage() {
  const [tenantId, setTenantId] = useState("");
  const [status, setStatus] = useState("");
  const [data, setData] = useState<Approval[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    if (!tenantId) return;
    setBusy(true);
    setError(null);
    try {
      setData(await adminApi.approvals.list({ tenant_id: tenantId, status: status || undefined }));
      setLoaded(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }, [tenantId, status]);

  const decide = useCallback(
    async (id: string, approve: boolean) => {
      const reason = window.prompt(
        `Reason for ${approve ? "approving" : "denying"} this action (required):`
      );
      if (reason === null) return; // cancelled
      if (!reason.trim()) {
        setError("A decision reason is required.");
        return;
      }
      setBusy(true);
      setError(null);
      try {
        await adminApi.approvals.decide(id, { tenant_id: tenantId, approve, reason });
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Request failed");
      } finally {
        setBusy(false);
      }
    },
    [tenantId, load]
  );

  const inputCls =
    "w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-1.5 text-sm text-neutral-100 placeholder:text-neutral-600";
  const btnCls =
    "rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-500 disabled:opacity-50";

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <h1 className="text-xl font-semibold">Approvals</h1>
      <p className="text-sm text-neutral-500">
        Fail-closed human-in-the-loop queue: a destructive/sensitive action is
        enqueued as <code>pending</code> and is not executable until approved.
        Every decision needs a mandatory reason and is written to the immutable
        audit log.
      </p>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <label className="block text-xs text-neutral-400">Tenant ID (UUID)</label>
          <input
            className={inputCls}
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
        <div>
          <label className="block text-xs text-neutral-400">Status filter</label>
          <select
            className={inputCls}
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="">all</option>
            <option value="pending">pending</option>
            <option value="approved">approved</option>
            <option value="denied">denied</option>
          </select>
        </div>
      </div>

      <button className={btnCls} onClick={load} disabled={busy || !tenantId}>
        Load approvals
      </button>

      {error && (
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      )}

      {loaded && (
        <DataTable<Approval>
          columns={[
            { key: "action", label: "Action" },
            { key: "target", label: "Target" },
            {
              key: "status",
              label: "Status",
              render: (r) => (
                <span
                  className={
                    r.status === "approved"
                      ? "text-green-400"
                      : r.status === "denied"
                        ? "text-red-400"
                        : "text-amber-400"
                  }
                >
                  {r.status}
                </span>
              ),
            },
            { key: "reason", label: "Reason", render: (r) => r.reason ?? "—" },
            { key: "decided_by", label: "Decided by", render: (r) => r.decided_by ?? "—" },
            { key: "decided_at", label: "Decided at", render: (r) => fmt(r.decided_at) },
            {
              key: "actions",
              label: "",
              render: (r) =>
                r.status === "pending" ? (
                  <div className="flex gap-2">
                    <button
                      className="rounded bg-green-900/60 px-2 py-1 text-xs text-green-200 hover:bg-green-800 disabled:opacity-50"
                      onClick={() => decide(r.id, true)}
                      disabled={busy}
                    >
                      Approve
                    </button>
                    <button
                      className="rounded bg-red-900/60 px-2 py-1 text-xs text-red-200 hover:bg-red-800 disabled:opacity-50"
                      onClick={() => decide(r.id, false)}
                      disabled={busy}
                    >
                      Deny
                    </button>
                  </div>
                ) : (
                  <span className="text-neutral-600">decided</span>
                ),
            },
          ]}
          data={data}
          emptyMessage="No approvals"
        />
      )}
    </div>
  );
}
