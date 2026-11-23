"use client";

import { useCallback, useState } from "react";
import { DataTable } from "@/components/DataTable";
import { adminApi, type Engagement } from "@/lib/api";

const splitCsv = (s: string): string[] =>
  s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

export default function EngagementsPage() {
  const [tenantId, setTenantId] = useState("");
  const [lookupId, setLookupId] = useState("");
  const [targets, setTargets] = useState("");
  const [tenants, setTenants] = useState("");
  const [actions, setActions] = useState("");
  const [maxRate, setMaxRate] = useState("");

  const [row, setRow] = useState<Engagement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async (fn: () => Promise<Engagement>) => {
    setBusy(true);
    setError(null);
    try {
      setRow(await fn());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }, []);

  const create = () =>
    run(() =>
      adminApi.engagements.create({
        tenant_id: tenantId,
        allowed_targets: splitCsv(targets),
        allowed_tenants: tenants ? splitCsv(tenants) : [tenantId],
        allowed_actions: splitCsv(actions),
        max_rate_per_target: maxRate ? Number(maxRate) : null,
      })
    );

  const lookup = () => run(() => adminApi.engagements.get(lookupId, tenantId));

  const revoke = (id: string) =>
    run(() => adminApi.engagements.revoke(id, tenantId));

  const inputCls =
    "w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-1.5 text-sm text-neutral-100 placeholder:text-neutral-600";
  const btnCls =
    "rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-500 disabled:opacity-50";

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <h1 className="text-xl font-semibold">Engagements</h1>
      <p className="text-sm text-neutral-500">
        Fail-closed scope: an engagement is deny-by-default. Only its allowed
        targets / tenants / actions pass the scope gate; revoked engagements deny
        everything.
      </p>

      <div className="space-y-2">
        <label className="block text-xs text-neutral-400">Tenant ID (UUID)</label>
        <input
          className={inputCls}
          value={tenantId}
          onChange={(e) => setTenantId(e.target.value)}
          placeholder="00000000-0000-0000-0000-000000000000"
        />
      </div>

      <div className="rounded border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
        <h2 className="text-sm font-medium text-neutral-300">Create engagement</h2>
        <input
          className={inputCls}
          value={targets}
          onChange={(e) => setTargets(e.target.value)}
          placeholder="allowed_targets (comma-separated hosts)"
        />
        <input
          className={inputCls}
          value={tenants}
          onChange={(e) => setTenants(e.target.value)}
          placeholder="allowed_tenants (comma-separated; defaults to tenant ID)"
        />
        <input
          className={inputCls}
          value={actions}
          onChange={(e) => setActions(e.target.value)}
          placeholder="allowed_actions (e.g. recon,vuln_analysis)"
        />
        <input
          className={inputCls}
          value={maxRate}
          onChange={(e) => setMaxRate(e.target.value)}
          placeholder="max_rate_per_target (optional, integer)"
        />
        <button className={btnCls} onClick={create} disabled={busy || !tenantId}>
          Create
        </button>
      </div>

      <div className="rounded border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
        <h2 className="text-sm font-medium text-neutral-300">Look up by ID</h2>
        <input
          className={inputCls}
          value={lookupId}
          onChange={(e) => setLookupId(e.target.value)}
          placeholder="engagement id"
        />
        <button className={btnCls} onClick={lookup} disabled={busy || !tenantId || !lookupId}>
          Look up
        </button>
      </div>

      {error && (
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      )}

      {row && (
        <DataTable<Engagement>
          columns={[
            { key: "id", label: "ID", render: (r) => <code className="text-xs">{r.id.slice(0, 8)}...</code> },
            { key: "allowed_targets", label: "Targets", render: (r) => r.allowed_targets.join(", ") || "—" },
            { key: "allowed_actions", label: "Actions", render: (r) => r.allowed_actions.join(", ") || "—" },
            { key: "max_rate_per_target", label: "Max rate", render: (r) => (r.max_rate_per_target ?? "—") },
            { key: "revoked", label: "Revoked", render: (r) => (r.revoked ? "Yes" : "No") },
            {
              key: "actions",
              label: "",
              render: (r) =>
                r.revoked ? (
                  <span className="text-neutral-600">revoked</span>
                ) : (
                  <button
                    className="rounded bg-red-900/60 px-2 py-1 text-xs text-red-200 hover:bg-red-800 disabled:opacity-50"
                    onClick={() => revoke(r.id)}
                    disabled={busy}
                  >
                    Revoke
                  </button>
                ),
            },
          ]}
          data={[row]}
        />
      )}
    </div>
  );
}
