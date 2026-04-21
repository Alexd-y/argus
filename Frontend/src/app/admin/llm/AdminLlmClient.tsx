"use client";

import { useCallback, useEffect, useId, useMemo, useState, useTransition } from "react";

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { getSafeErrorMessage } from "@/lib/api";
import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import {
  createLlmProviderRow,
  getLlmRuntimeSummary,
  listLlmProvidersForTenant,
  patchLlmProvider,
  type AdminLlmProviderRow,
  type LlmRuntimeSummary,
} from "./actions";

const ADDABLE_PROVIDER_KEYS = [
  "openai",
  "deepseek",
  "openrouter",
  "kimi",
  "perplexity",
  "google",
  "anthropic",
] as const;

function errMsg(e: unknown): string {
  return getSafeErrorMessage(e, "Operation failed.");
}

function formatKeyDisplay(row: AdminLlmProviderRow): string {
  if (!row.api_key_set) return "—";
  if (row.api_key_last4) return `***${row.api_key_last4}`;
  return "***";
}

function AdminLlmBody() {
  const [isPending, startTransition] = useTransition();
  const tenantSelectId = useId();

  const [tenants, setTenants] = useState<AdminTenant[]>([]);
  const [tenantId, setTenantId] = useState<string>("");
  const [runtime, setRuntime] = useState<LlmRuntimeSummary | null>(null);
  const [rows, setRows] = useState<AdminLlmProviderRow[]>([]);
  const [listError, setListError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [newKey, setNewKey] = useState<string>(ADDABLE_PROVIDER_KEYS[0]);
  const [editKey, setEditKey] = useState<string>("");
  const [editFallback, setEditFallback] = useState<string>("");
  const [editingId, setEditingId] = useState<string | null>(null);

  const loadTenants = useCallback(() => {
    startTransition(async () => {
      try {
        const t = await listTenants({ limit: 200, offset: 0 });
        setTenants(t);
        setTenantId((cur) => {
          if (cur && t.some((x) => x.id === cur)) return cur;
          return t[0]?.id ?? "";
        });
      } catch (e) {
        setListError(errMsg(e));
        setTenants([]);
      }
    });
  }, []);

  const loadRuntime = useCallback(() => {
    startTransition(async () => {
      try {
        setRuntime(await getLlmRuntimeSummary());
      } catch {
        setRuntime(null);
      }
    });
  }, []);

  const refreshProviders = useCallback(() => {
    if (!tenantId.trim()) {
      setRows([]);
      return;
    }
    setListError(null);
    startTransition(async () => {
      try {
        setRows(await listLlmProvidersForTenant(tenantId.trim()));
      } catch (e) {
        setListError(errMsg(e));
        setRows([]);
      }
    });
  }, [tenantId]);

  useEffect(() => {
    loadTenants();
    loadRuntime();
  }, [loadTenants, loadRuntime]);

  useEffect(() => {
    refreshProviders();
  }, [refreshProviders]);

  const openEdit = (r: AdminLlmProviderRow) => {
    setActionError(null);
    setEditingId(r.id);
    setEditKey("");
    setEditFallback((r.model_fallback_chain ?? []).join(", "));
  };

  const closeEdit = () => {
    setEditingId(null);
    setEditKey("");
    setEditFallback("");
  };

  const saveEdit = () => {
    if (!editingId) return;
    setActionError(null);
    const raw = editFallback.trim();
    let chain: string[] | null;
    if (!raw) {
      chain = [];
    } else {
      chain = raw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }
    setBusyId(editingId);
    startTransition(async () => {
      try {
        await patchLlmProvider({
          providerId: editingId,
          apiKey: editKey.trim() ? editKey : undefined,
          modelFallbackChain: chain,
        });
        closeEdit();
        refreshProviders();
      } catch (e) {
        setActionError(errMsg(e));
      } finally {
        setBusyId(null);
      }
    });
  };

  const toggleEnabled = (r: AdminLlmProviderRow) => {
    setActionError(null);
    setBusyId(r.id);
    startTransition(async () => {
      try {
        await patchLlmProvider({ providerId: r.id, enabled: !r.enabled });
        refreshProviders();
      } catch (e) {
        setActionError(errMsg(e));
      } finally {
        setBusyId(null);
      }
    });
  };

  const addProvider = () => {
    if (!tenantId.trim()) return;
    setActionError(null);
    setBusyId("__add__");
    startTransition(async () => {
      try {
        await createLlmProviderRow({ tenantId: tenantId.trim(), providerKey: newKey });
        refreshProviders();
      } catch (e) {
        setActionError(errMsg(e));
      } finally {
        setBusyId(null);
      }
    });
  };

  const missingKeys = useMemo(
    () =>
      ADDABLE_PROVIDER_KEYS.filter(
        (k) => !rows.some((r) => r.provider_key.toLowerCase() === k),
      ),
    [rows],
  );

  useEffect(() => {
    if (missingKeys.length === 0) return;
    const ok = missingKeys.some((k) => k === newKey);
    if (!ok) setNewKey(missingKeys[0]);
  }, [missingKeys, newKey]);

  return (
    <div className="space-y-4">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">LLM providers</h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Per-tenant provider rows and secrets. API keys are write-only; responses show last four
            characters only.
          </p>
        </div>

        {runtime?.execution_uses_global_env ? (
          <div
            className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
            role="status"
          >
            <span className="font-medium text-[var(--text-primary)]">Runtime note: </span>
            The orchestration stack currently resolves LLM calls from{' '}
            <span className="text-[var(--text-primary)]">global environment variables</span>.
            Per-tenant keys stored here are not yet wired into the worker; they are persisted for
            upcoming tenant-scoped routing.
          </div>
        ) : null}

        {runtime ? (
          <div className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3 text-xs text-[var(--text-muted)]">
            <div className="mb-1 font-medium text-[var(--text-secondary)]">
              Global env (process) — configured flags only
            </div>
            <ul className="grid gap-1 sm:grid-cols-2 md:grid-cols-3">
              {Object.entries(runtime.global_env_providers).map(([k, on]) => (
                <li key={k}>
                  <span className="text-[var(--text-primary)]">{k}</span>
                  {on ? (
                    <span className="text-[var(--text-muted)]"> — set</span>
                  ) : (
                    <span className="text-[var(--text-muted)]"> — not set</span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[12rem] flex-1">
            <label className="text-xs text-[var(--text-muted)]" htmlFor={tenantSelectId}>
              Tenant
            </label>
            <select
              id={tenantSelectId}
              className="mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              disabled={isPending && tenants.length === 0}
            >
              {tenants.length === 0 ? <option value="">No tenants</option> : null}
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.id.slice(0, 8)}…)
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
              value={missingKeys.length === 0 ? "" : newKey}
              onChange={(e) => setNewKey(e.target.value)}
              disabled={!tenantId || missingKeys.length === 0}
            >
              {missingKeys.length === 0 ? (
                <option value="">All providers added</option>
              ) : (
                missingKeys.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))
              )}
            </select>
            <button
              type="button"
              className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50"
              disabled={!tenantId || missingKeys.length === 0 || busyId !== null}
              onClick={addProvider}
            >
              Add provider
            </button>
          </div>
        </div>

        {listError ? (
          <div className="rounded border border-red-900/40 bg-red-950/20 px-3 py-2 text-sm text-red-200">
            {listError}
          </div>
        ) : null}
        {actionError ? (
          <div className="rounded border border-red-900/40 bg-red-950/20 px-3 py-2 text-sm text-red-200">
            {actionError}
          </div>
        ) : null}

        {!tenantId ? (
          <p className="text-sm text-[var(--text-muted)]">Select a tenant to manage providers.</p>
        ) : (
          <div className="overflow-x-auto rounded border border-[var(--border)]">
            <table className="w-full min-w-[640px] border-collapse text-left text-sm">
              <thead className="border-b border-[var(--border)] bg-[var(--bg-secondary)] text-xs text-[var(--text-muted)]">
                <tr>
                  <th className="px-3 py-2 font-medium">Provider</th>
                  <th className="px-3 py-2 font-medium">Enabled</th>
                  <th className="px-3 py-2 font-medium">API key</th>
                  <th className="px-3 py-2 font-medium">Model fallback</th>
                  <th className="px-3 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-3 py-6 text-center text-[var(--text-muted)]">
                      No provider rows for this tenant. Add one above.
                    </td>
                  </tr>
                ) : null}
                {rows.map((r) => (
                  <tr key={r.id} className="border-b border-[var(--border)]">
                    <td className="px-3 py-2 font-medium text-[var(--text-primary)]">
                      {r.provider_key}
                    </td>
                    <td className="px-3 py-2 text-[var(--text-secondary)]">
                      {r.enabled ? "yes" : "no"}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-[var(--text-secondary)]">
                      {formatKeyDisplay(r)}
                    </td>
                    <td className="px-3 py-2 text-[var(--text-secondary)]">
                      {r.model_fallback_chain && r.model_fallback_chain.length > 0 ? (
                        <span className="text-xs">{r.model_fallback_chain.join(" → ")}</span>
                      ) : (
                        <span className="text-[var(--text-muted)]">Not configured</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          className="rounded border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)] disabled:opacity-50"
                          disabled={busyId !== null}
                          onClick={() => toggleEnabled(r)}
                        >
                          {r.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          type="button"
                          className="rounded border border-[var(--border)] px-2 py-1 text-xs text-[var(--accent)] hover:bg-[var(--bg-tertiary)] disabled:opacity-50"
                          disabled={busyId !== null}
                          onClick={() => openEdit(r)}
                        >
                          Edit key / chain
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {editingId ? (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
            role="dialog"
            aria-modal="true"
          >
            <div className="w-full max-w-md rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4 shadow-lg">
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                Update provider secret / fallback
              </h2>
              <p className="mt-1 text-xs text-[var(--text-muted)]">
                Leave API key blank to keep the current secret. Use comma-separated model ids for the
                fallback chain (empty clears the chain).
              </p>
              <label className="mt-3 block text-xs text-[var(--text-muted)]">
                New API key (optional)
                <input
                  type="password"
                  autoComplete="off"
                  className="mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
                  value={editKey}
                  onChange={(e) => setEditKey(e.target.value)}
                />
              </label>
              <label className="mt-3 block text-xs text-[var(--text-muted)]">
                Model fallback chain (comma-separated)
                <input
                  className="mt-1 w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
                  value={editFallback}
                  onChange={(e) => setEditFallback(e.target.value)}
                  placeholder="gpt-4o-mini, gpt-4o"
                />
              </label>
              <div className="mt-4 flex flex-wrap justify-end gap-2">
                <button
                  type="button"
                  className="rounded border border-[var(--border)] px-3 py-1.5 text-sm text-[var(--text-secondary)] disabled:opacity-50"
                  disabled={busyId !== null}
                  onClick={() => {
                    if (!editingId) return;
                    setActionError(null);
                    setBusyId(editingId);
                    startTransition(async () => {
                      try {
                        await patchLlmProvider({ providerId: editingId, apiKey: "" });
                        closeEdit();
                        refreshProviders();
                      } catch (e) {
                        setActionError(errMsg(e));
                      } finally {
                        setBusyId(null);
                      }
                    });
                  }}
                >
                  Remove API key
                </button>
                <button
                  type="button"
                  className="rounded border border-[var(--border)] px-3 py-1.5 text-sm text-[var(--text-secondary)]"
                  onClick={closeEdit}
                  disabled={busyId !== null}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-[var(--bg-primary)] disabled:opacity-50"
                  onClick={saveEdit}
                  disabled={busyId !== null}
                >
                  Save
                </button>
              </div>
            </div>
          </div>
        ) : null}
    </div>
  );
}

export function AdminLlmClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <AdminLlmBody />
    </AdminRouteGuard>
  );
}
